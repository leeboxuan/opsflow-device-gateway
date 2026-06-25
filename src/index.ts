import "dotenv/config";
import net from "node:net";

const tcpPort = Number(process.env.TCP_PORT ?? "8088");
const opsflowApiUrl = process.env.OPSFLOW_API_URL?.trim() ?? "";
const deviceGatewayKey = process.env.DEVICE_GATEWAY_KEY?.trim() ?? "";

if (!opsflowApiUrl) {
  console.warn("[startup] OPSFLOW_API_URL is empty; LOCATION POST will fail until configured.");
}

if (!deviceGatewayKey) {
  console.warn("[startup] DEVICE_GATEWAY_KEY is empty; backend auth header will be blank.");
}

console.log(`[startup] OPSFLOW_API_URL loaded: ${Boolean(opsflowApiUrl)}`);
console.log(`[startup] DEVICE_GATEWAY_KEY loaded: ${Boolean(deviceGatewayKey)}`);
console.log(`[startup] DEVICE_GATEWAY_KEY length: ${deviceGatewayKey.length}`);

const START_FLAG = 0x7e;
const inboundCacheBySocket = new WeakMap<net.Socket, Buffer>();
const activeSockets = new Set<net.Socket>();
let serverSerial = 1;
let totalPacketsReceived = 0;
let totalLocationPacketsParsed = 0;
let totalSuccessfulBackendPosts = 0;
let totalFailedBackendPosts = 0;
let isShuttingDown = false;

type Jt808Header = {
  messageId: number;
  bodyLength: number;
  terminalIdRaw: Buffer;
  terminalId: string;
  serialNo: number;
};

type ParsedLocation = {
  lat: number;
  lng: number;
  speedKph: number;
  heading: number;
  altitude: number;
  recordedAt: string;
};

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toBcdString(data: Buffer): string {
  let out = "";
  for (const byte of data) {
    out += ((byte >> 4) & 0x0f).toString(10);
    out += (byte & 0x0f).toString(10);
  }
  return out;
}

function fromBcdString(digits: string): Buffer {
  const normalized = digits.length % 2 === 0 ? digits : `0${digits}`;
  const out = Buffer.alloc(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    out[i / 2] = (Number(normalized[i]) << 4) | Number(normalized[i + 1]);
  }
  return out;
}

function xorChecksum(data: Buffer): number {
  let sum = 0;
  for (const b of data) {
    sum ^= b;
  }
  return sum;
}

function escapeJt808(data: Buffer): Buffer {
  const out: number[] = [];
  for (const byte of data) {
    if (byte === 0x7e) {
      out.push(0x7d, 0x02);
    } else if (byte === 0x7d) {
      out.push(0x7d, 0x01);
    } else {
      out.push(byte);
    }
  }
  return Buffer.from(out);
}

function unescapeJt808(data: Buffer): Buffer {
  const out: number[] = [];
  for (let i = 0; i < data.length; i += 1) {
    const byte = data[i];
    if (byte === 0x7d && i + 1 < data.length) {
      const next = data[i + 1];
      if (next === 0x01) {
        out.push(0x7d);
        i += 1;
        continue;
      }
      if (next === 0x02) {
        out.push(0x7e);
        i += 1;
        continue;
      }
    }
    out.push(byte);
  }
  return Buffer.from(out);
}

function parseHeader(packetNoFlag: Buffer): Jt808Header | null {
  if (packetNoFlag.length < 12) {
    return null;
  }

  const messageId = packetNoFlag.readUInt16BE(0);
  const bodyProps = packetNoFlag.readUInt16BE(2);
  const bodyLength = bodyProps & 0x03ff;
  const terminalIdRaw = Buffer.from(packetNoFlag.subarray(4, 10));
  const terminalId = toBcdString(terminalIdRaw);
  const serialNo = packetNoFlag.readUInt16BE(10);

  return { messageId, bodyLength, terminalIdRaw, terminalId, serialNo };
}

function nextSerial(): number {
  const next = serverSerial & 0xffff;
  serverSerial = (serverSerial + 1) & 0xffff;
  if (serverSerial === 0) {
    serverSerial = 1;
  }
  return next;
}

function buildPacket(
  messageId: number,
  terminalIdRaw: Buffer,
  serialNo: number,
  body: Buffer,
): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(messageId, 0);
  header.writeUInt16BE(body.length, 2);
  terminalIdRaw.copy(header, 4);
  header.writeUInt16BE(serialNo, 10);

  const content = Buffer.concat([header, body]);
  const checksum = Buffer.from([xorChecksum(content)]);
  const escaped = escapeJt808(Buffer.concat([content, checksum]));
  return Buffer.concat([Buffer.from([START_FLAG]), escaped, Buffer.from([START_FLAG])]);
}

function buildCommonAck(
  incomingHeader: Jt808Header,
  result: number,
): Buffer {
  const body = Buffer.alloc(5);
  body.writeUInt16BE(incomingHeader.serialNo, 0);
  body.writeUInt16BE(incomingHeader.messageId, 2);
  body.writeUInt8(result, 4);

  return buildPacket(0x8001, incomingHeader.terminalIdRaw, nextSerial(), body);
}

function buildRegisterAck(incomingHeader: Jt808Header): Buffer {
  const auth = Buffer.from("opsflow", "ascii");
  const body = Buffer.alloc(3 + auth.length);
  body.writeUInt16BE(incomingHeader.serialNo, 0);
  body.writeUInt8(0, 2);
  auth.copy(body, 3);

  return buildPacket(0x8100, incomingHeader.terminalIdRaw, nextSerial(), body);
}

function parseBcdDateTimeYYMMDDhhmmss(data: Buffer): string {
  if (data.length < 6) {
    return new Date(0).toISOString();
  }

  const two = (b: number): number => ((b >> 4) & 0x0f) * 10 + (b & 0x0f);
  const year = 2000 + two(data[0]);
  const month = two(data[1]);
  const day = two(data[2]);
  const hour = two(data[3]);
  const minute = two(data[4]);
  const second = two(data[5]);

  return new Date(Date.UTC(year, Math.max(0, month - 1), day, hour, minute, second)).toISOString();
}

function parseLocation0200(body: Buffer): ParsedLocation | null {
  if (body.length < 28) {
    return null;
  }

  const lat = body.readUInt32BE(8) / 1_000_000;
  const lng = body.readUInt32BE(12) / 1_000_000;
  const altitude = body.readUInt16BE(16);
  const speedKph = body.readUInt16BE(18) / 10;
  const heading = body.readUInt16BE(20);
  const recordedAt = parseBcdDateTimeYYMMDDhhmmss(body.subarray(22, 28));

  return { lat, lng, speedKph, heading, altitude, recordedAt };
}

function isValidLocation(location: ParsedLocation): boolean {
  const validLat = location.lat >= -90 && location.lat <= 90;
  const validLng = location.lng >= -180 && location.lng <= 180;
  const validRecordedAt = !Number.isNaN(Date.parse(location.recordedAt));
  return validLat && validLng && validRecordedAt;
}

async function postLocationEvent(
  terminalId: string,
  location: ParsedLocation,
  hex: string,
  messageHex: string,
): Promise<void> {
  const url = `${opsflowApiUrl.replace(/\/+$/, "")}/internal/device-gateway/events`;
  const payload = {
    protocol: "JT808",
    deviceType: "GPS_TRACKER",
    terminalId,
    event: "LOCATION",
    payload: {
      lat: location.lat,
      lng: location.lng,
      speedKph: location.speedKph,
      heading: location.heading,
      altitude: location.altitude,
      recordedAt: location.recordedAt,
      rawMessageId: "0x0200",
      rawPayload: {
        hex,
      },
    },
  };
  const retryDelaysMs = [0, 500, 1500];

  for (let attempt = 0; attempt < retryDelaysMs.length; attempt += 1) {
    if (retryDelaysMs[attempt] > 0) {
      await delay(retryDelaysMs[attempt]);
    }

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-gateway-key": deviceGatewayKey,
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        totalSuccessfulBackendPosts += 1;
        console.log(
          `[gateway] post success terminalId=${terminalId} messageId=${messageHex} lat=${location.lat} lng=${location.lng} recordedAt=${location.recordedAt} attempt=${attempt + 1}`,
        );
        return;
      }

      const body = await response.text();
      const httpError = `POST ${response.status} ${response.statusText} - ${body}`;
      if (response.status >= 500 && attempt < retryDelaysMs.length - 1) {
        console.warn(
          `[gateway] post retry terminalId=${terminalId} messageId=${messageHex} attempt=${attempt + 1} reason=${httpError}`,
        );
        continue;
      }

      totalFailedBackendPosts += 1;
      throw new Error(httpError);
    } catch (error: unknown) {
      if (attempt < retryDelaysMs.length - 1) {
        console.warn(
          `[gateway] post retry terminalId=${terminalId} messageId=${messageHex} attempt=${attempt + 1} error=${String(error)}`,
        );
        continue;
      }
      totalFailedBackendPosts += 1;
      throw error;
    }
  }
}

function extractFrames(buffer: Buffer): { frames: Buffer[]; rest: Buffer } {
  const frames: Buffer[] = [];
  let start = -1;
  let cursor = 0;

  while (cursor < buffer.length) {
    if (buffer[cursor] === START_FLAG) {
      if (start === -1) {
        start = cursor;
      } else {
        const frame = buffer.subarray(start + 1, cursor);
        if (frame.length > 0) {
          frames.push(frame);
        }
        start = cursor;
      }
    }
    cursor += 1;
  }

  if (start === -1) {
    return { frames, rest: Buffer.alloc(0) };
  }

  const rest = buffer.subarray(start);
  return { frames, rest };
}

function processFrame(socket: net.Socket, rawFrame: Buffer): void {
  totalPacketsReceived += 1;
  const decoded = unescapeJt808(rawFrame);
  if (decoded.length < 13) {
    return;
  }

  const packetNoChecksum = decoded.subarray(0, decoded.length - 1);
  const checksum = decoded[decoded.length - 1];
  const expected = xorChecksum(packetNoChecksum);
  if (checksum !== expected) {
    console.warn("[jt808] checksum mismatch; packet dropped");
    return;
  }

  const header = parseHeader(packetNoChecksum);
  if (!header) {
    return;
  }

  const body = packetNoChecksum.subarray(12, 12 + header.bodyLength);
  const messageHex = `0x${header.messageId.toString(16).padStart(4, "0")}`;

  console.log(`[jt808] recv messageId=${messageHex} terminalId=${header.terminalId} serialNo=${header.serialNo}`);

  if (header.messageId === 0x0100) {
    const ack8100 = buildRegisterAck(header);
    socket.write(ack8100);
    console.log(`[jt808] sent messageId=0x8100 terminalId=${header.terminalId}`);
    console.log(`[jt808] ack hex messageId=0x8100 terminalId=${header.terminalId} hex=${ack8100.toString("hex")}`);
    return;
  }

  if (header.messageId === 0x0200) {
    const location = parseLocation0200(body);
    if (location) {
      totalLocationPacketsParsed += 1;
      if (!isValidLocation(location)) {
        console.warn(
          `[jt808] invalid location terminalId=${header.terminalId} messageId=${messageHex} lat=${location.lat} lng=${location.lng} recordedAt=${location.recordedAt}`,
        );
      } else {
        postLocationEvent(header.terminalId, location, packetNoChecksum.toString("hex"), messageHex)
        .then(() => {
          // success log is emitted inside postLocationEvent with detailed payload context.
        })
        .catch((error: unknown) => {
          console.error(
            `[gateway] post failure terminalId=${header.terminalId} messageId=${messageHex} lat=${location.lat} lng=${location.lng} recordedAt=${location.recordedAt} error=${String(error)}`,
          );
        });
      }
    } else {
      console.warn(`[jt808] invalid 0x0200 body terminalId=${header.terminalId}`);
    }
  }

  const ack8001 = buildCommonAck(header, 0);
  socket.write(ack8001);
  console.log(`[jt808] sent messageId=0x8001 terminalId=${header.terminalId} for=${messageHex}`);
  console.log(`[jt808] ack hex messageId=0x8001 terminalId=${header.terminalId} for=${messageHex} hex=${ack8001.toString("hex")}`);
}

const server = net.createServer((socket) => {
  const addr = `${socket.remoteAddress ?? "unknown"}:${socket.remotePort ?? "unknown"}`;
  console.log(`[tcp] client connected ${addr}`);
  activeSockets.add(socket);
  inboundCacheBySocket.set(socket, Buffer.alloc(0));

  socket.on("data", (chunk) => {
    const current = inboundCacheBySocket.get(socket) ?? Buffer.alloc(0);
    const combined = Buffer.concat([current, chunk]);
    const { frames, rest } = extractFrames(combined);
    inboundCacheBySocket.set(socket, rest);

    for (const frame of frames) {
      processFrame(socket, frame);
    }
  });

  socket.on("close", () => {
    inboundCacheBySocket.delete(socket);
    activeSockets.delete(socket);
    console.log(`[tcp] client disconnected ${addr}`);
  });

  socket.on("error", (err) => {
    console.error(`[tcp] socket error ${addr} error=${err.message}`);
  });
});

server.on("error", (err) => {
  console.error(`[tcp] server error ${err.message}`);
});

server.listen(tcpPort, () => {
  console.log(`[startup] opsflow-device-gateway listening on TCP ${tcpPort}`);
});

const healthInterval = setInterval(() => {
  console.log(
    `[health] sockets=${activeSockets.size} packets=${totalPacketsReceived} locations=${totalLocationPacketsParsed} posts_ok=${totalSuccessfulBackendPosts} posts_failed=${totalFailedBackendPosts}`,
  );
}, 60_000);

function shutdown(signal: string): void {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;
  console.log(`[shutdown] signal=${signal} stopping gateway`);
  clearInterval(healthInterval);

  server.close((err?: Error) => {
    if (err) {
      console.error(`[shutdown] server close error=${err.message}`);
      process.exit(1);
      return;
    }
    console.log("[shutdown] tcp server closed");
    process.exit(0);
  });

  for (const socket of activeSockets) {
    socket.end();
    setTimeout(() => {
      if (!socket.destroyed) {
        socket.destroy();
      }
    }, 2000);
  }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

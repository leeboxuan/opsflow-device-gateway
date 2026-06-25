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

const START_FLAG = 0x7e;
const msgSerialBySocket = new WeakMap<net.Socket, number>();
const inboundCacheBySocket = new WeakMap<net.Socket, Buffer>();

type Jt808Header = {
  messageId: number;
  bodyLength: number;
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
  const terminalId = toBcdString(packetNoFlag.subarray(4, 10));
  const serialNo = packetNoFlag.readUInt16BE(10);

  return { messageId, bodyLength, terminalId, serialNo };
}

function nextSerial(socket: net.Socket): number {
  const current = msgSerialBySocket.get(socket) ?? 0;
  const next = (current + 1) & 0xffff;
  msgSerialBySocket.set(socket, next);
  return next;
}

function buildPacket(
  messageId: number,
  terminalId: string,
  serialNo: number,
  body: Buffer,
): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(messageId, 0);
  header.writeUInt16BE(body.length & 0x03ff, 2);
  fromBcdString(terminalId.padStart(12, "0").slice(-12)).copy(header, 4);
  header.writeUInt16BE(serialNo, 10);

  const content = Buffer.concat([header, body]);
  const checksum = Buffer.from([xorChecksum(content)]);
  const escaped = escapeJt808(Buffer.concat([content, checksum]));
  return Buffer.concat([Buffer.from([START_FLAG]), escaped, Buffer.from([START_FLAG])]);
}

function buildCommonAck(
  incomingHeader: Jt808Header,
  result: number,
  socket: net.Socket,
): Buffer {
  const body = Buffer.alloc(5);
  body.writeUInt16BE(incomingHeader.serialNo, 0);
  body.writeUInt16BE(incomingHeader.messageId, 2);
  body.writeUInt8(result, 4);

  return buildPacket(0x8001, incomingHeader.terminalId, nextSerial(socket), body);
}

function buildRegisterAck(incomingHeader: Jt808Header, socket: net.Socket): Buffer {
  const auth = Buffer.from("opsflow", "ascii");
  const body = Buffer.alloc(5 + auth.length);
  body.writeUInt16BE(incomingHeader.serialNo, 0);
  body.writeUInt16BE(0x0100, 2);
  body.writeUInt8(0, 4);
  auth.copy(body, 5);

  return buildPacket(0x8100, incomingHeader.terminalId, nextSerial(socket), body);
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

async function postLocationEvent(terminalId: string, location: ParsedLocation, hex: string): Promise<void> {
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

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-device-gateway-key": deviceGatewayKey,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`POST ${response.status} ${response.statusText} - ${body}`);
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
    socket.write(buildRegisterAck(header, socket));
    console.log(`[jt808] sent messageId=0x8100 terminalId=${header.terminalId}`);
    return;
  }

  if (header.messageId === 0x0200) {
    const location = parseLocation0200(body);
    if (location) {
      postLocationEvent(header.terminalId, location, packetNoChecksum.toString("hex"))
        .then(() => {
          console.log(`[gateway] post success messageId=${messageHex} terminalId=${header.terminalId}`);
        })
        .catch((error: unknown) => {
          console.error(
            `[gateway] post failure messageId=${messageHex} terminalId=${header.terminalId} error=${String(error)}`,
          );
        });
    } else {
      console.warn(`[jt808] invalid 0x0200 body terminalId=${header.terminalId}`);
    }
  }

  socket.write(buildCommonAck(header, 0, socket));
  console.log(`[jt808] sent messageId=0x8001 terminalId=${header.terminalId} for=${messageHex}`);
}

const server = net.createServer((socket) => {
  const addr = `${socket.remoteAddress ?? "unknown"}:${socket.remotePort ?? "unknown"}`;
  console.log(`[tcp] client connected ${addr}`);
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
    msgSerialBySocket.delete(socket);
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

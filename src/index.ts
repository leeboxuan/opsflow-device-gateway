import "dotenv/config";
import net from "node:net";

const tcpPort = Number(process.env.TCP_PORT ?? "8088");
const opsflowApiUrl = process.env.OPSFLOW_API_URL?.trim() ?? "";
const deviceGatewayKey = process.env.DEVICE_GATEWAY_KEY?.trim() ?? "";
const debugJt808Extras = process.env.DEBUG_JT808_EXTRAS === "true";

if (!opsflowApiUrl) {
  console.warn("[startup] OPSFLOW_API_URL is empty; LOCATION POST will fail until configured.");
}

if (!deviceGatewayKey) {
  console.warn("[startup] DEVICE_GATEWAY_KEY is empty; backend auth header will be blank.");
}

console.log(`[startup] OPSFLOW_API_URL loaded: ${Boolean(opsflowApiUrl)}`);
console.log(`[startup] DEVICE_GATEWAY_KEY loaded: ${Boolean(deviceGatewayKey)}`);
console.log(`[startup] DEVICE_GATEWAY_KEY length: ${deviceGatewayKey.length}`);
console.log(`[startup] DEBUG_JT808_EXTRAS: ${debugJt808Extras}`);

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
  batteryVoltageMv?: number;
  batteryVoltage?: number;
  batteryPercent?: number;
  signalStrength?: number;
  satelliteCount?: number;
};

type AdditionalInfoField = {
  fieldId: number;
  length: number;
  value: Buffer;
};

const LOCATION_0200_BASE_BODY_LENGTH = 28;
const TK905B_EB_FIELD_ID = 0xeb;
const TK905B_EB_BATTERY_VOLTAGE_OFFSET = 34;
const TK905B_EB_BATTERY_PERCENT_OFFSET = 40;
const TK905B_EB_MIN_LENGTH_FOR_BATTERY = 36;
const TK905B_EB_MIN_LENGTH_FOR_BATTERY_PERCENT = 41;
const BATTERY_VOLTAGE_MV_MIN = 3000;
const BATTERY_VOLTAGE_MV_MAX = 4500;
const BATTERY_PERCENT_MIN = 0;
const BATTERY_PERCENT_MAX = 100;

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

function parse0200AdditionalInfo(
  body: Buffer,
  terminalId: string,
): { rawHex: string; fields: AdditionalInfoField[] } {
  const extras = body.subarray(LOCATION_0200_BASE_BODY_LENGTH);
  const fields: AdditionalInfoField[] = [];
  let offset = 0;

  while (offset + 2 <= extras.length) {
    const fieldId = extras[offset];
    const length = extras[offset + 1];
    if (offset + 2 + length > extras.length) {
      console.warn(
        `[jt808] extras parse truncated terminalId=${terminalId} fieldId=0x${fieldId.toString(16).padStart(2, "0")} offset=${offset}`,
      );
      break;
    }

    const value = extras.subarray(offset + 2, offset + 2 + length);
    fields.push({
      fieldId,
      length,
      value,
    });
    offset += 2 + length;
  }

  return { rawHex: extras.toString("hex"), fields };
}

function parse0200HealthExtras(fields: AdditionalInfoField[]): Pick<
  ParsedLocation,
  "batteryVoltageMv" | "batteryVoltage" | "batteryPercent" | "signalStrength" | "satelliteCount"
> {
  const extras: Pick<
    ParsedLocation,
    "batteryVoltageMv" | "batteryVoltage" | "batteryPercent" | "signalStrength" | "satelliteCount"
  > = {};

  for (const field of fields) {
    if (field.fieldId === 0x30 && field.length >= 1) {
      extras.signalStrength = field.value[0];
    }

    if (field.fieldId === 0x31 && field.length >= 1) {
      extras.satelliteCount = field.value[0];
    }

    if (field.fieldId === TK905B_EB_FIELD_ID) {
      if (field.length >= TK905B_EB_MIN_LENGTH_FOR_BATTERY) {
        const batteryVoltageMv = field.value.readUInt16BE(TK905B_EB_BATTERY_VOLTAGE_OFFSET);
        if (batteryVoltageMv >= BATTERY_VOLTAGE_MV_MIN && batteryVoltageMv <= BATTERY_VOLTAGE_MV_MAX) {
          extras.batteryVoltageMv = batteryVoltageMv;
          extras.batteryVoltage = batteryVoltageMv / 1000;
        }
      }

      if (field.length >= TK905B_EB_MIN_LENGTH_FOR_BATTERY_PERCENT) {
        const batteryPercent = field.value[TK905B_EB_BATTERY_PERCENT_OFFSET];
        if (batteryPercent >= BATTERY_PERCENT_MIN && batteryPercent <= BATTERY_PERCENT_MAX) {
          extras.batteryPercent = batteryPercent;
        }
      }
    }
  }

  return extras;
}

function logPossibleTlv(
  data: Buffer,
  terminalId: string,
  messageSequence: number,
  scheme: string,
  idLen: number,
  lenLen: number,
): void {
  const fields: string[] = [];
  let offset = 0;
  const headerLen = idLen + lenLen;

  while (offset + headerLen <= data.length) {
    let fieldId: number;
    let fieldLen: number;

    if (idLen === 1 && lenLen === 1) {
      fieldId = data[offset];
      fieldLen = data[offset + 1];
    } else if (idLen === 2 && lenLen === 2) {
      fieldId = data.readUInt16BE(offset);
      fieldLen = data.readUInt16BE(offset + 2);
    } else if (idLen === 2 && lenLen === 1) {
      fieldId = data.readUInt16BE(offset);
      fieldLen = data[offset + 2];
    } else {
      return;
    }

    if (fieldLen < 0 || offset + headerLen + fieldLen > data.length) {
      fields.push(`truncated@offset=${offset}`);
      break;
    }

    const value = data.subarray(offset + headerLen, offset + headerLen + fieldLen);
    const idHex =
      idLen === 1
        ? `0x${fieldId.toString(16).padStart(2, "0")}`
        : `0x${fieldId.toString(16).padStart(4, "0")}`;
    fields.push(`${idHex} len=${fieldLen} hex=${value.toString("hex")}`);
    offset += headerLen + fieldLen;
  }

  if (offset < data.length && fields.length > 0) {
    fields.push(`remaining=${data.subarray(offset).toString("hex")}`);
  }

  const summary = fields.length > 0 ? fields.join("; ") : "no complete TLV fields parsed";
  console.log(
    `[jt808] extras 0xeb tlv terminalId=${terminalId} sequence=${messageSequence} scheme=${scheme} ${summary}`,
  );
}

function log0xEbFieldDebug(terminalId: string, messageSequence: number, fieldHex: string): void {
  const data = Buffer.from(fieldHex, "hex");

  console.log(
    `[jt808] extras 0xeb debug terminalId=${terminalId} sequence=${messageSequence} length=${data.length} rawHex=${fieldHex}`,
  );

  console.log(`[jt808] extras 0xeb bytes terminalId=${terminalId} sequence=${messageSequence} count=${data.length}`);
  for (let i = 0; i < data.length; i += 1) {
    const u8 = data[i];
    const i8 = u8 > 127 ? u8 - 256 : u8;
    console.log(
      `[jt808] extras 0xeb byte terminalId=${terminalId} sequence=${messageSequence} offset=${i} hex=${u8.toString(16).padStart(2, "0")} uint8=${u8} int8=${i8}`,
    );
  }

  if (data.length >= 2) {
    for (let i = 0; i <= data.length - 2; i += 1) {
      const u16 = data.readUInt16BE(i);
      const i16 = data.readInt16BE(i);
      console.log(
        `[jt808] extras 0xeb u16 window terminalId=${terminalId} sequence=${messageSequence} offset=${i} uint16BE=${u16} int16BE=${i16}`,
      );
    }
  }

  if (data.length >= 4) {
    for (let i = 0; i <= data.length - 4; i += 1) {
      const u32 = data.readUInt32BE(i);
      const i32 = data.readInt32BE(i);
      console.log(
        `[jt808] extras 0xeb u32 window terminalId=${terminalId} sequence=${messageSequence} offset=${i} uint32BE=${u32} int32BE=${i32}`,
      );
    }
  }

  logPossibleTlv(data, terminalId, messageSequence, "id1-len1", 1, 1);
  logPossibleTlv(data, terminalId, messageSequence, "id2-len2", 2, 2);
  logPossibleTlv(data, terminalId, messageSequence, "id2-len1", 2, 1);

  const percentCandidates: string[] = [];
  const voltageCandidates: string[] = [];

  for (let i = 0; i < data.length; i += 1) {
    const u8 = data[i];
    if (u8 >= 0 && u8 <= 100) {
      percentCandidates.push(`offset=${i} uint8=${u8}`);
    }
  }

  for (let i = 0; i <= data.length - 2; i += 1) {
    const u16 = data.readUInt16BE(i);
    if (u16 >= 3700 && u16 <= 4300) {
      voltageCandidates.push(`offset=${i} uint16BE=${u16}mV`);
    }
    if (u16 >= 37 && u16 <= 43) {
      voltageCandidates.push(`offset=${i} uint16BE=${u16}(tenths/decivolts)`);
    }
  }

  console.log(
    `[jt808] extras 0xeb battery candidates terminalId=${terminalId} sequence=${messageSequence} percent=[${percentCandidates.join(", ") || "none"}] voltage=[${voltageCandidates.join(", ") || "none"}]`,
  );
}

function log0200ExtrasDebug(terminalId: string, messageSequence: number, body: Buffer): void {
  const { rawHex, fields } = parse0200AdditionalInfo(body, terminalId);

  console.log(
    `[jt808] extras debug terminalId=${terminalId} sequence=${messageSequence} rawAdditionalInfoHex=${rawHex || "(empty)"}`,
  );

  if (fields.length === 0) {
    console.log(`[jt808] extras debug terminalId=${terminalId} sequence=${messageSequence} fieldIds=(none)`);
    return;
  }

  const fieldIds = fields.map((field) => `0x${field.fieldId.toString(16).padStart(2, "0")}`).join(",");
  console.log(`[jt808] extras debug terminalId=${terminalId} sequence=${messageSequence} fieldIds=${fieldIds}`);

  for (const field of fields) {
    const fieldHex = field.value.toString("hex");
    console.log(
      `[jt808] extras field terminalId=${terminalId} sequence=${messageSequence} fieldId=0x${field.fieldId.toString(16).padStart(2, "0")} length=${field.length} hex=${fieldHex}`,
    );

    if (field.fieldId === TK905B_EB_FIELD_ID) {
      log0xEbFieldDebug(terminalId, messageSequence, fieldHex);
    }
  }
}

function parseLocation0200(body: Buffer, terminalId: string): ParsedLocation | null {
  if (body.length < LOCATION_0200_BASE_BODY_LENGTH) {
    return null;
  }

  const lat = body.readUInt32BE(8) / 1_000_000;
  const lng = body.readUInt32BE(12) / 1_000_000;
  const altitude = body.readUInt16BE(16);
  const speedKph = body.readUInt16BE(18) / 10;
  const heading = body.readUInt16BE(20);
  const recordedAt = parseBcdDateTimeYYMMDDhhmmss(body.subarray(22, 28));
  const { fields } = parse0200AdditionalInfo(body, terminalId);
  const healthExtras = parse0200HealthExtras(fields);

  return { lat, lng, speedKph, heading, altitude, recordedAt, ...healthExtras };
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
  const locationPayload: Record<string, unknown> = {
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
  };

  if (location.batteryVoltageMv !== undefined) {
    locationPayload.batteryVoltageMv = location.batteryVoltageMv;
  }
  if (location.batteryVoltage !== undefined) {
    locationPayload.batteryVoltage = location.batteryVoltage;
  }
  if (location.batteryPercent !== undefined) {
    locationPayload.batteryPercent = location.batteryPercent;
  }
  if (location.signalStrength !== undefined) {
    locationPayload.signalStrength = location.signalStrength;
  }
  if (location.satelliteCount !== undefined) {
    locationPayload.satelliteCount = location.satelliteCount;
  }

  const payload = {
    protocol: "JT808",
    deviceType: "GPS_TRACKER",
    terminalId,
    event: "LOCATION",
    payload: locationPayload,
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
        const batteryLog =
          location.batteryVoltageMv !== undefined
            ? ` batteryVoltageMv=${location.batteryVoltageMv}`
            : "";
        const percentLog =
          location.batteryPercent !== undefined ? ` batteryPercent=${location.batteryPercent}` : "";
        console.log(
          `[gateway] post success terminalId=${terminalId} messageId=${messageHex} lat=${location.lat} lng=${location.lng} recordedAt=${location.recordedAt}${batteryLog}${percentLog} attempt=${attempt + 1}`,
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
    if (debugJt808Extras) {
      log0200ExtrasDebug(header.terminalId, header.serialNo, body);
    }

    const location = parseLocation0200(body, header.terminalId);
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

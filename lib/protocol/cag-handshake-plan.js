'use strict';

const crypto = require('crypto');
const {
  decodeZteCagRadiusConnectInfoBody,
  encodeZteCagOpentelemetryLocalKeyPacket,
  encodeZteCagRadiusConnectInfoBody,
  encodeZteCagUdpControlDatagram,
  parseZteCagDatagram,
  ZteCagAuthType,
} = require('./zte-cag');

function parseUint32(value, name) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new Error(`${name} must be a uint32`);
    }
    return value >>> 0;
  }
  const text = String(value).trim();
  const n = text.startsWith('0x') || /[a-f]/i.test(text)
    ? Number.parseInt(text.replace(/^0x/i, ''), 16)
    : Number(text);
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`${name} must be a uint32`);
  }
  return n >>> 0;
}

function uint32LeBuffer(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value >>> 0, 0);
  return out;
}

function routeIdFromRandomKey(randomKey) {
  return Buffer.concat([Buffer.alloc(3), uint32LeBuffer(randomKey)]);
}

function lengthControlWord(payloadLength) {
  return ((Number(payloadLength) & 0xff) << 8) & 0xffff;
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function packetSummary(buffer, opts = {}) {
  const summary = {
    length: buffer.length,
    sha256: sha256Hex(buffer),
  };
  if (opts.showHex) summary.hex = buffer.toString('hex');
  return summary;
}

function createLocalKeyDatagram(opts = {}) {
  const randomKey = parseUint32(opts.randomKey, 'randomKey') ?? crypto.randomBytes(4).readUInt32LE(0);
  const clientKey = opts.clientKey ? Buffer.from(String(opts.clientKey).replace(/^0x/i, ''), 'hex') : crypto.randomBytes(16);
  if (clientKey.length !== 16) throw new Error('clientKey must be 16 bytes hex');

  const payload = encodeZteCagOpentelemetryLocalKeyPacket({
    authType: ZteCagAuthType.RADIUS,
    randomKey,
    clientKey,
    baseFlags: opts.baseFlags === undefined ? 0x04 : Number(opts.baseFlags),
    transportFlag: opts.transportFlag === undefined ? 0x0b : Number(opts.transportFlag),
    addressFamilyFlag: opts.addressFamilyFlag === undefined ? 0x0b : Number(opts.addressFamilyFlag),
    traceId: opts.traceId || randomHex(16),
    spanId: opts.spanId || randomHex(8),
  });
  const routeId = routeIdFromRandomKey(randomKey);
  const datagram = encodeZteCagUdpControlDatagram({
    type: 0x06,
    sequence: opts.sequence === undefined ? 1 : Number(opts.sequence),
    routeId,
    tunnelId: 0,
    controlWord: 0,
    payload,
  });
  return {
    randomKey,
    clientKey,
    routeId,
    datagram,
    parsed: parseZteCagDatagram(datagram),
  };
}

function createConnectInfoDatagram(auth = {}, opts = {}) {
  const randomKey = parseUint32(opts.randomKey, 'randomKey');
  const serverKey = parseUint32(opts.serverKey, 'serverKey');
  const tunnelId = parseUint32(opts.tunnelId, 'tunnelId');
  if (randomKey === null) throw new Error('randomKey is required for connect_info');
  if (serverKey === null) throw new Error('serverKey is required for connect_info');
  if (tunnelId === null) throw new Error('tunnelId is required for connect_info');

  const payload = encodeZteCagRadiusConnectInfoBody({
    vmcPort: auth.vmcPort,
    vmcIp: auth.vmcIp,
    vmId: auth.vmId || auth.vmID,
    username: auth.vmUserName,
    password: auth.vmPassword,
    clientKey: randomKey,
    serverKey,
    aesFlags: opts.aesFlags === undefined ? 1 : Number(opts.aesFlags),
  });
  const datagram = encodeZteCagUdpControlDatagram({
    type: 0x08,
    sequence: opts.sequence === undefined ? 0 : Number(opts.sequence),
    routeId: routeIdFromRandomKey(randomKey),
    tunnelId,
    controlWord: opts.controlWord === undefined ? 0 : Number(opts.controlWord),
    payload,
  });
  return {
    datagram,
    payload,
    parsedConnectInfo: decodeZteCagRadiusConnectInfoBody(payload, {
      clientKey: randomKey,
      serverKey,
      aesFlags: opts.aesFlags === undefined ? 1 : Number(opts.aesFlags),
    }),
  };
}

function createCagHandshakePlan(auth = {}, opts = {}) {
  const localKey = createLocalKeyDatagram({
    ...opts,
    sequence: opts.localKeySequence === undefined ? opts.sequence : opts.localKeySequence,
  });
  const showHex = String(opts.showHex || '0') === '1';
  const plan = {
    safe: {
      sendsPackets: false,
      sdkStarted: false,
      desktopConnectSent: false,
      spiceAuthSent: false,
    },
    localKey: {
      type: 'local_key',
      randomKeyHex: `0x${localKey.randomKey.toString(16).padStart(8, '0')}`,
      clientKeyHex: localKey.clientKey.toString('hex'),
      routeIdHex: localKey.routeId.toString('hex'),
      datagram: packetSummary(localKey.datagram, { showHex }),
      ztecOffset: localKey.parsed.ztecOffset,
      connectInfoLength: localKey.parsed.ztecOpentelemetryKeyInfo?.connectInfoLength,
      traceId: localKey.parsed.ztecOpentelemetryKeyInfo?.traceId || '',
      spanId: localKey.parsed.ztecOpentelemetryKeyInfo?.spanId || '',
    },
    serverKeyRequired: {
      requiredForConnectInfo: true,
      fields: ['serverKey', 'tunnelId'],
    },
  };

  if (opts.serverKey !== undefined && opts.tunnelId !== undefined) {
    const connectInfo = createConnectInfoDatagram(auth, {
      ...opts,
      randomKey: localKey.randomKey,
      sequence: opts.connectInfoSequence === undefined ? opts.sequence : opts.connectInfoSequence,
    });
    plan.connectInfo = {
      type: 'connect_info',
      datagram: packetSummary(connectInfo.datagram, { showHex }),
      payloadLength: connectInfo.payload.length,
      vmId: connectInfo.parsedConnectInfo.vmId,
      vmcIp: connectInfo.parsedConnectInfo.ip,
      vmcPort: connectInfo.parsedConnectInfo.port,
      usernamePresent: Boolean(connectInfo.parsedConnectInfo.username),
      passwordPresent: Boolean(auth.vmPassword),
    };
  }

  return plan;
}

module.exports = {
  createCagHandshakePlan,
  createConnectInfoDatagram,
  createLocalKeyDatagram,
  lengthControlWord,
  parseUint32,
  routeIdFromRandomKey,
};

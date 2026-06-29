'use strict';

const assert = require('assert');
const crypto = require('crypto');

const {
  CHUANYUN_HEAD_SIZE,
  ChuanyunChannel,
  ChuanyunFrameType,
  ProtocolStage,
  SpiceMessage,
  applyProtocolEvent,
  buildScgAuthCiphertext,
  buildScgAuthPacket,
  buildScgAuthPlaintext,
  classifyProtocolRoute,
  createProtocolProgress,
  createCagHandshakePlan,
  createConnectInfoDatagram,
  createLocalKeyDatagram,
  createCemHeaders,
  createProtocolProbeReport,
  decodeZteCagOpentelemetryLocalKeyBody,
  decodeZteCagRadiusConnectInfoBody,
  decodeZteCagServerKeyPacket,
  deriveZteCagAesMaterial,
  deriveZteCagTunnelMeta,
  decodeChuanyunFrame,
  decodeChuanyunHead,
  decodeCapabilityWords,
  decodeDataHeader,
  decodeDataMessage,
  decodeLocalSpiceClientHandshake,
  decodeLocalSpiceClientDataMessages,
  decodeLocalSpiceExtInfo,
  decodeLocalSpiceServerDataMessages,
  decodeLocalSpiceServerHandshake,
  decodeMiniMessage,
  decodeSetAckPayload,
  decodeSpiceAuthResult,
  decodeSpiceLinkHeader,
  decodeSpiceLinkMess,
  decodeSpiceLinkReply,
  encodeAck,
  encodeAckSync,
  encodeCapabilityWords,
  encodeDataHeader,
  encodeDataMessage,
  encryptCemPayload,
  encodeChuanyunFrame,
  encodeChuanyunHead,
  encodeDisplayInit,
  encodeMiniHeader,
  encodePong,
  encodeSpiceLinkHeader,
  encodeSpiceLinkMess,
  encodeZteCagTunnelHeader,
  encodeZteCagRadiusConnectInfoBody,
  encodeZteCagOpentelemetryLocalKeyPacket,
  encodeZteCagLocalKeyPacket,
  encodeZteCagPacket,
  encodeZteCagUdpControlDatagram,
  encodeZteCagUdpControlHeader,
  isProtocolKeepaliveSuccess,
  looksLikeZteCagTunnelDatagram,
  readDerObjectLength,
  normalizeProtocolConnectInfo,
  parseZteCagDatagram,
  parseZteCagConnectReply,
  parseZteCagTunnelDatagram,
  parseZteCagUdpControlDatagram,
  parseScgAuthResponse,
  SpiceChannel,
  SpiceCommonCapability,
  summarizeZteCagTunnelDatagrams,
  summarizeZteCagTunnelSequences,
  xorZteCagPassword,
  ZteCagTunnelType,
  routeIdFromRandomKey,
  zteCagConnectInfoLength,
  zteCagPasswordBlockLength,
} = require('../lib/protocol');

const connectInfo = normalizeProtocolConnectInfo({
  vmId: 'vm-123',
  scAuthCode: 'sc-auth',
  cagIp: '111.31.3.182',
  cagPort: 8899,
  scgIp: '',
  scgTcpPort: 0,
});
assert.deepStrictEqual({
  vmId: connectInfo.vmId,
  scAuthCode: connectInfo.scAuthCode,
  host: connectInfo.host,
  port: connectInfo.port,
  source: connectInfo.source,
}, {
  vmId: 'vm-123',
  scAuthCode: 'sc-auth',
  host: '111.31.3.182',
  port: 8899,
  source: 'cag',
});

const scgPlaintext = buildScgAuthPlaintext({
  scAuthCode: 'auth-code',
  vmId: 'vm-123',
  timestamp: 1_700_000_000,
});
assert.strictEqual(scgPlaintext.toString('hex'), '0002000000006553f100030009617574682d636f64657c766d2d313233');
assert.strictEqual(scgPlaintext.subarray(13, 22).toString(), 'auth-code');
const scgCiphertext = buildScgAuthCiphertext({
  scAuthCode: 'auth-code',
  vmId: 'vm-123',
  timestamp: 1_700_000_000,
  key: Buffer.alloc(16, 1),
  iv: Buffer.alloc(16, 2),
});
assert.notStrictEqual(scgCiphertext.toString('hex'), scgPlaintext.toString('hex'));
const scgPacket = buildScgAuthPacket({
  scAuthCode: 'auth-code',
  vmId: 'vm-123',
  timestamp: 1_700_000_000,
  key: Buffer.alloc(16, 1),
  iv: Buffer.alloc(16, 2),
});
assert.strictEqual(scgPacket[0], 0x01);
assert.strictEqual(scgPacket[1], scgCiphertext.length & 0xff);
assert.strictEqual(scgPacket.subarray(2).toString('hex'), scgCiphertext.toString('hex'));
const scgResponse = parseScgAuthResponse(Buffer.from('000102030405', 'hex'), { sessionOffset: 2, sessionLength: 3 });
assert.strictEqual(scgResponse.ok, true);
assert.strictEqual(scgResponse.sessionId, 0x020304n);

assert.deepStrictEqual(
  classifyProtocolRoute({ scgIp: '1.2.3.4', scgTcpPort: 10800 }).route,
  'blog-scg'
);
assert.deepStrictEqual(
  classifyProtocolRoute({ scgIp: '1.2.3.4', scgTcpPort: 1443 }).route,
  'scg-other'
);
assert.deepStrictEqual(
  classifyProtocolRoute({ cagIp: '111.31.3.182', cagPort: 8899 }).route,
  'linux-cag'
);
const probeReport = createProtocolProbeReport({
  userServiceId: '2663816',
  auth: {
    vmId: 'vm-123',
    scAuthCode: 'sc-auth',
    cagIp: '111.31.3.182',
    cagPort: 8899,
  },
  env: {},
});
assert.strictEqual(probeReport.route.route, 'linux-cag');
assert.strictEqual(probeReport.connectInfo.accessCredentialPresent, true);
assert.strictEqual(probeReport.connectInfo.accessCredentialSource, 'scAuthCode');
assert.strictEqual(probeReport.connectInfo.vmPasswordAsCredential, false);
assert.strictEqual(probeReport.safe.sdkStarted, false);
assert.strictEqual(probeReport.safe.desktopConnectSent, false);
assert.ok(probeReport.cemProbe.missing.includes('YDY_CEM_BASE_URL'));
const cagPasswordProbeReport = createProtocolProbeReport({
  userServiceId: '2663816',
  auth: {
    vmId: 'vm-123',
    vmPassword: 'sdk-password',
    cagIp: '111.31.3.182',
    cagPort: 8899,
  },
  env: {},
});
assert.strictEqual(cagPasswordProbeReport.connectInfo.accessCredentialPresent, true);
assert.strictEqual(cagPasswordProbeReport.connectInfo.accessCredentialSource, 'vmPassword');
assert.strictEqual(cagPasswordProbeReport.connectInfo.scAuthCodePresent, false);
assert.strictEqual(cagPasswordProbeReport.connectInfo.vmPasswordAsCredential, true);

const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
const cemEncrypted = encryptCemPayload({ code: 'sc-auth' }, publicKey.export({ type: 'spki', format: 'pem' }));
assert.match(cemEncrypted, /^\{rsa\}/);
assert.ok(Buffer.from(cemEncrypted.slice(5), 'base64').length >= 128);
assert.deepStrictEqual(createCemHeaders({
  clientId: 'client-id',
  terminalSn: 'device-id',
  accessToken: 'token',
  timestamp: 1,
  unitType: 'Linux',
}), {
  Authorization: 'Bearer token',
  'gzs-client-id': 'client-id',
  'gzs-timestamp': '1',
  'sc-terminal-sn': 'device-id',
  'sc-network-type': '2',
  'sc-unit-type': 'Linux',
});

const ztecDatagram = parseZteCagDatagram(Buffer.from('5a54454306007c020a0a2e2700001a1da6040000000033b2151d', 'hex'));
assert.strictEqual(ztecDatagram.hasZtec, true);
assert.strictEqual(ztecDatagram.ztecOffset, 0);
assert.strictEqual(ztecDatagram.hasTlsRecord, false);

const zteTunnelDatagram = parseZteCagDatagram(Buffer.from(
  'e1db878d81000150000000000000000000000005020000001603010200010001fc03039f152d897da44b',
  'hex'
));
assert.strictEqual(zteTunnelDatagram.hasTlsRecord, true);
assert.strictEqual(zteTunnelDatagram.tlsOffset, 24);
assert.strictEqual(zteTunnelDatagram.tunnelHeader.word0, 0xe1db878d);
assert.strictEqual(zteTunnelDatagram.tunnelHeader.word1, 0x81000150);
assert.strictEqual(zteTunnelDatagram.tunnelHeader.word4, 0x00000005);
assert.strictEqual(zteTunnelDatagram.tunnelHeader.packetType, ZteCagTunnelType.DATA);
assert.strictEqual(zteTunnelDatagram.tunnelHeader.packetTypeName, 'data');
assert.strictEqual(zteTunnelDatagram.tunnelHeader.flagByte, 0);
assert.strictEqual(zteTunnelDatagram.tunnelHeader.sequence16, 0x0150);
assert.strictEqual(zteTunnelDatagram.tunnel.payloadLength, 18);
assert.strictEqual(zteTunnelDatagram.tunnel.payloadLengthMatchesWord4, false);
assert.strictEqual(zteTunnelDatagram.tunnel.tlsRecordOffset, 0);
assert.strictEqual(zteTunnelDatagram.tlsRecord.subarray(0, 5).toString('hex'), '1603010200');
assert.strictEqual(encodeZteCagTunnelHeader(zteTunnelDatagram.tunnelHeader).toString('hex'), 'e1db878d8100015000000000000000000000000502000000');

const dynamicMagicTunnel = parseZteCagDatagram(Buffer.from(
  '34db078781000160000000000000000000000005020000001603010200',
  'hex',
));
assert.strictEqual(looksLikeZteCagTunnelDatagram(dynamicMagicTunnel.tunnel.header.raw), true);
assert.strictEqual(dynamicMagicTunnel.tunnel.header.word0, 0x34db0787);
assert.strictEqual(dynamicMagicTunnel.tunnel.header.packetType, ZteCagTunnelType.DATA);
assert.strictEqual(dynamicMagicTunnel.tunnel.hasTlsRecord, true);
assert.strictEqual(dynamicMagicTunnel.tunnel.tlsRecordOffset, 0);

const observedAckTunnel = parseZteCagTunnelDatagram(Buffer.from(
  'e1db878d86000100000000e8030000020000000000000000',
  'hex',
));
assert.strictEqual(observedAckTunnel.header.packetType, ZteCagTunnelType.ACK);
assert.strictEqual(observedAckTunnel.header.packetTypeName, 'ack');
assert.strictEqual(observedAckTunnel.payloadLength, 0);
assert.strictEqual(observedAckTunnel.payloadLengthMatchesWord4, true);
const observedAckMeta = deriveZteCagTunnelMeta(observedAckTunnel);
assert.strictEqual(observedAckMeta.ackValue, 0xe8);
assert.strictEqual(observedAckMeta.ackValueHex, '0x000000e8');

const observedShortControlTunnel = parseZteCagDatagram(Buffer.from(
  '34db0787820001600000000000000000000000000100',
  'hex',
));
assert.strictEqual(observedShortControlTunnel.udpControl, undefined);
assert.strictEqual(observedShortControlTunnel.tunnel.short, true);
assert.strictEqual(observedShortControlTunnel.tunnel.header.packetType, ZteCagTunnelType.CONTROL);
assert.strictEqual(observedShortControlTunnel.tunnel.header.packetTypeName, 'control');
assert.strictEqual(observedShortControlTunnel.tunnel.header.word0, 0x34db0787);
assert.strictEqual(observedShortControlTunnel.tunnel.header.sequence16, 0x0160);
const observedShortControlMeta = deriveZteCagTunnelMeta(observedShortControlTunnel.tunnel);
assert.strictEqual(observedShortControlMeta.short, true);
assert.strictEqual(observedShortControlMeta.shortTailHex, '0100');

const observedClientControlTunnel = parseZteCagTunnelDatagram(Buffer.from(
  'e1db878d89000000000000000000000000000022000000000400000000000000000000019f14392b240400000000000100000002001a0003001e',
  'hex',
));
assert.strictEqual(observedClientControlTunnel.header.packetType, ZteCagTunnelType.CLIENT_CONTROL);
assert.strictEqual(observedClientControlTunnel.header.packetTypeName, 'client_control');
assert.strictEqual(observedClientControlTunnel.payloadLength, 34);
assert.strictEqual(observedClientControlTunnel.payloadLengthMatchesWord4, true);
assert.deepStrictEqual(summarizeZteCagTunnelDatagrams([
  { direction: 'C>S', payload: Buffer.from('e1db878d81000150000000000000000000000005020000001603010200010001fc03039f152d897da44b', 'hex') },
  { direction: 'C>S', payload: Buffer.from('e1db878d86000100000000e8030000020000000000000000', 'hex') },
  { direction: 'C>S', payload: Buffer.from('e1db878d89000000000000000000000000000022000000000400000000000000000000019f14392b240400000000000100000002001a0003001e', 'hex') },
]), {
  total: 3,
  countsByType: { data: 1, ack: 1, client_control: 1 },
  countsByDirectionAndType: { 'C>S:data': 1, 'C>S:ack': 1, 'C>S:client_control': 1 },
  tlsRecords: 1,
  payloadLengthMatchesWord4: 2,
  ackPackets: 1,
  clientControlPackets: 1,
});
const repeatedDataSummary = summarizeZteCagTunnelSequences([
  { direction: 'C>S', payload: Buffer.from('34db078781000160000000000000000000000005020000001603010200', 'hex') },
  { direction: 'C>S', payload: Buffer.from('34db078781000160000000000100000000000005020000001703030010', 'hex') },
  { direction: 'S>C', payload: Buffer.from('34db078786000100000000e8000000000000000000000000', 'hex') },
  { direction: 'C>S', payload: Buffer.from('34db0787820001600000000000000000000000000100', 'hex') },
]);
assert.strictEqual(repeatedDataSummary.total, 4);
assert.strictEqual(repeatedDataSummary.byDirection['C>S'].data.count, 2);
assert.strictEqual(repeatedDataSummary.byDirection['C>S'].control.count, 1);
assert.strictEqual(repeatedDataSummary.byDirection['S>C'].ack.count, 1);
assert.strictEqual(repeatedDataSummary.dataSequences.length, 1);
assert.strictEqual(repeatedDataSummary.dataSequences[0].sequence16, 0x0160);
assert.strictEqual(repeatedDataSummary.dataSequences[0].count, 2);
assert.strictEqual(repeatedDataSummary.dataSequences[0].tlsRecords, 2);
assert.strictEqual(repeatedDataSummary.ackValues[0].ackValue, 0xe8);
assert.strictEqual(repeatedDataSummary.shortControls[0].shortTailHex, '0100');

assert.strictEqual(zteCagPasswordBlockLength(0), 0);
assert.strictEqual(zteCagPasswordBlockLength(8), 32);
assert.strictEqual(zteCagConnectInfoLength({ authType: 1 }), 0xdc);
assert.strictEqual(zteCagConnectInfoLength({ authType: 2, passwordLength: 8 }), 0x9e);

const zteLocalKeyPacket = encodeZteCagLocalKeyPacket({
  authType: 2,
  randomKey: 0x01020304,
  clientKey: Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'),
  passwordLength: 8,
  transportFlag: 0x12,
  addressFamilyFlag: 0x34,
});
assert.strictEqual(zteLocalKeyPacket.length, 0x32);
assert.strictEqual(zteLocalKeyPacket.subarray(0, 6).toString('hex'), '5a5445432c00');
assert.strictEqual(zteLocalKeyPacket.readUInt32LE(6), 0x66);
assert.strictEqual(zteLocalKeyPacket.readUInt32LE(10), 0x01020304);
assert.strictEqual(zteLocalKeyPacket.readUInt32LE(14), 0x9e);
assert.strictEqual(zteLocalKeyPacket.subarray(18, 34).toString('hex'), '000102030405060708090a0b0c0d0e0f');
assert.strictEqual(zteLocalKeyPacket.readUInt32LE(34), 0x34120003);

const observedOpentelemetryBody = Buffer.from(
  '650000002ad54b2fdc000000f8ec01000d4c33479ff0b4e32f9cbcbd04000b0b000000000000000000000000' +
  '38396434343564323236353862366136353533663663646564643339663531380000000000000000000000000000000000000000000000000000000000000000' +
  '37656439303036396265616132313831000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
const observedOpentelemetry = decodeZteCagOpentelemetryLocalKeyBody(observedOpentelemetryBody);
assert.strictEqual(observedOpentelemetry.firstWord, 0x65);
assert.strictEqual(observedOpentelemetry.key, 0x2f4bd52a);
assert.strictEqual(observedOpentelemetry.connectInfoLength, 0xdc);
assert.strictEqual(observedOpentelemetry.clientKey.toString('hex'), 'f8ec01000d4c33479ff0b4e32f9cbcbd');
assert.strictEqual(observedOpentelemetry.flags, 0x0b0b0004);
assert.strictEqual(observedOpentelemetry.traceId, '89d445d22658b6a6553f6cdedd39f518');
assert.strictEqual(observedOpentelemetry.spanId, '7ed90069beaa2181');
const encodedOpentelemetryPacket = encodeZteCagOpentelemetryLocalKeyPacket({
  authType: 1,
  randomKey: 0x2f4bd52a,
  clientKey: Buffer.from('f8ec01000d4c33479ff0b4e32f9cbcbd', 'hex'),
  baseFlags: 0x04,
  transportFlag: 0x0b,
  addressFamilyFlag: 0x0b,
  traceId: '89d445d22658b6a6553f6cdedd39f518',
  spanId: '7ed90069beaa2181',
});
assert.strictEqual(encodedOpentelemetryPacket.subarray(0, 6).toString('hex'), '5a544543ac00');
assert.strictEqual(encodedOpentelemetryPacket.subarray(6).toString('hex'), observedOpentelemetryBody.toString('hex'));

const observedControlPayload = Buffer.concat([
  Buffer.from('06000080000000010000002ad54b2f000000000000', 'hex'),
  encodedOpentelemetryPacket,
]);
assert.strictEqual(routeIdFromRandomKey(0x2f4bd52a).toString('hex'), '0000002ad54b2f');
const plannedLocalKey = createLocalKeyDatagram({
  randomKey: '0x2f4bd52a',
  clientKey: 'f8ec01000d4c33479ff0b4e32f9cbcbd',
  traceId: '89d445d22658b6a6553f6cdedd39f518',
  spanId: '7ed90069beaa2181',
});
assert.strictEqual(plannedLocalKey.datagram.toString('hex'), observedControlPayload.toString('hex'));
const observedControl = parseZteCagUdpControlDatagram(observedControlPayload);
assert.strictEqual(observedControl.header.type, 0x06);
assert.strictEqual(observedControl.header.flags24.toString('hex'), '000080');
assert.strictEqual(observedControl.header.sequence, 1);
assert.strictEqual(observedControl.header.routeId.toString('hex'), '0000002ad54b2f');
assert.strictEqual(observedControl.header.tunnelId, 0);
assert.strictEqual(observedControl.payload.subarray(0, 6).toString('hex'), '5a544543ac00');
assert.strictEqual(encodeZteCagUdpControlHeader(observedControl.header).toString('hex'), '06000080000000010000002ad54b2f000000000000');
assert.strictEqual(encodeZteCagUdpControlDatagram({
  ...observedControl.header,
  payload: encodedOpentelemetryPacket,
}).toString('hex'), observedControlPayload.toString('hex'));
const observedControlDatagram = parseZteCagDatagram(observedControlPayload);
assert.strictEqual(observedControlDatagram.ztecOffset, 21);
assert.strictEqual(observedControlDatagram.udpControl.header.sequence, 1);
assert.strictEqual(observedControlDatagram.udpControl.header.typeName, 'local_key');
assert.strictEqual(observedControlDatagram.ztecOpentelemetryKeyInfo.traceId, '89d445d22658b6a6553f6cdedd39f518');

const observedServerKeyControlPayload = Buffer.from(
  '0700008000000000000000447b290534db07873200' +
  '5a544543240065000000dac3214f00000000000000000000000000000000000000000300000000000000',
  'hex',
);
const observedServerKeyControl = parseZteCagUdpControlDatagram(observedServerKeyControlPayload);
assert.strictEqual(observedServerKeyControl.header.type, 0x07);
assert.strictEqual(observedServerKeyControl.header.typeName, 'server_key');
assert.strictEqual(observedServerKeyControl.header.routeId.toString('hex'), '000000447b2905');
assert.strictEqual(observedServerKeyControl.header.tunnelId, 0x34db0787);
assert.strictEqual(observedServerKeyControl.dynamicTunnelWord0, 0x34db0787);
assert.strictEqual(observedServerKeyControl.ztecPacket.head.bodyLength, 0x24);
assert.strictEqual(observedServerKeyControl.ztecServerKeyInfo.key, 0x4f21c3da);
assert.strictEqual(observedServerKeyControl.ztecServerKeyInfo.sdkAesFlags, 0x102);
const observedServerKeyDatagram = parseZteCagDatagram(observedServerKeyControlPayload);
assert.strictEqual(observedServerKeyDatagram.dynamicTunnelWord0, 0x34db0787);
assert.strictEqual(observedServerKeyDatagram.ztecServerKeyInfo.key, 0x4f21c3da);

const observedConnectReplyControlPayload = Buffer.from(
  '0900008000000000000000447b290534db07872400' +
  'c8000000010000000e020a0aff3e16fa0000000000000000000000000000000000000000',
  'hex',
);
const observedConnectReplyControl = parseZteCagDatagram(observedConnectReplyControlPayload);
assert.strictEqual(observedConnectReplyControl.udpControl.header.typeName, 'connect_reply');
assert.strictEqual(observedConnectReplyControl.udpControl.header.tunnelId, 0x34db0787);
assert.strictEqual(observedConnectReplyControl.connectReply.ok, true);
assert.strictEqual(observedConnectReplyControl.connectReply.code, 200);

const zteServerBody = Buffer.alloc(0x2c);
zteServerBody.writeUInt32LE(0x02030405, 4);
zteServerBody.writeUInt32LE(0x00000003, 0x1c);
const zteServerKeyPacket = decodeZteCagServerKeyPacket(encodeZteCagPacket(zteServerBody));
assert.strictEqual(zteServerKeyPacket.head.ok, true);
assert.strictEqual(zteServerKeyPacket.keyInfo.key, 0x02030405);
assert.strictEqual(zteServerKeyPacket.keyInfo.aesType, 2);
assert.strictEqual(zteServerKeyPacket.keyInfo.useCbc, true);
assert.strictEqual(zteServerKeyPacket.keyInfo.sdkAesFlags, 0x102);

const observedServerKeyPacket = decodeZteCagServerKeyPacket(Buffer.from(
  '5a5445432400650000007657ed4d000000000000000000000000000000000000000003000000000000000000000000000000',
  'hex',
));
assert.strictEqual(observedServerKeyPacket.keyInfo.key, 0x4ded5776);
assert.strictEqual(
  observedServerKeyPacket.keyInfo.sdkAesFlags,
  0x102,
  'observed UDP opentelemetry server-key packet carries CBC/AES-256-style flags',
);

const zteAesMaterial = deriveZteCagAesMaterial({
  clientKey: 0x01020304,
  serverKey: 0x05060708,
  aesFlags: 0x102,
});
assert.strictEqual(zteAesMaterial.bits, 256);
assert.strictEqual(zteAesMaterial.useCbc, true);
assert.strictEqual(zteAesMaterial.ivString.length, 17);
assert.strictEqual(zteAesMaterial.iv.length, 16);
assert.strictEqual(zteAesMaterial.key.length, 32);

assert.strictEqual(xorZteCagPassword(Buffer.from('abc', 'ascii')).toString('hex'), '020163');

const observedConnectInfoBody = Buffer.from(
  'ec1300000a0a027c00000000000000000000000031363363363861392d356531652d346362612d623962622d36386164353939613861626600000000' +
  'a4a1a63aa21e46945fb7901f4591169afd7a70ec8a752935b0dfda4439bf260bfd7a70ec8a752935b0dfda4439bf260bfd7a70ec8a752935b0dfda4439bf260b' +
  '92a7736f2b82f8078eae4e451e562bec54ddb994f42fc2f9a002c6b0efebfdcf8b012d24a1d9dbb07a7dc7d018aa4c30fd7a70ec8a752935b0dfda4439bf260b' +
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const observedConnectInfo = decodeZteCagRadiusConnectInfoBody(observedConnectInfoBody, {
  clientKey: 0x2f4bd52a,
  serverKey: observedServerKeyPacket.keyInfo.key,
  aesFlags: 1,
});
assert.strictEqual(observedConnectInfo.port, 0x13ec);
assert.strictEqual(observedConnectInfo.ip, '10.10.2.124');
assert.strictEqual(observedConnectInfo.vmId, '163c68a9-5e1e-4cba-b9bb-68ad599a8abf');
assert.strictEqual(observedConnectInfo.username, '6573655444aff86f');
assert.notStrictEqual(observedConnectInfo.encryptedPassword.toString('hex'), Buffer.alloc(0x40).toString('hex'));
const plannedConnectInfo = createConnectInfoDatagram({
  vmcPort: observedConnectInfo.port,
  vmcIp: observedConnectInfo.ip,
  vmId: observedConnectInfo.vmId,
  vmUserName: observedConnectInfo.username,
}, {
  randomKey: 0x2f4bd52a,
  serverKey: observedServerKeyPacket.keyInfo.key,
  tunnelId: 0x34db0787,
  aesFlags: 1,
});
assert.strictEqual(plannedConnectInfo.payload.length, 0xdc);
assert.strictEqual(plannedConnectInfo.datagram[0], 0x08);
assert.strictEqual(plannedConnectInfo.datagram.subarray(8, 15).toString('hex'), '0000002ad54b2f');
assert.strictEqual(plannedConnectInfo.datagram.readUInt32BE(15), 0x34db0787);
assert.strictEqual(plannedConnectInfo.parsedConnectInfo.username, observedConnectInfo.username);
const reencodedObservedConnectInfoWithoutPassword = encodeZteCagRadiusConnectInfoBody({
  vmcPort: observedConnectInfo.port,
  vmcIp: observedConnectInfo.ip,
  vmId: observedConnectInfo.vmId,
  username: observedConnectInfo.username,
  clientKey: 0x2f4bd52a,
  serverKey: observedServerKeyPacket.keyInfo.key,
  aesFlags: 1,
});
assert.strictEqual(
  reencodedObservedConnectInfoWithoutPassword.subarray(0, 0x7c).toString('hex'),
  observedConnectInfoBody.subarray(0, 0x7c).toString('hex'),
);
assert.strictEqual(
  reencodedObservedConnectInfoWithoutPassword.subarray(0xbc).toString('hex'),
  observedConnectInfoBody.subarray(0xbc).toString('hex'),
);
const offlineHandshakePlan = createCagHandshakePlan({
  vmcPort: observedConnectInfo.port,
  vmcIp: observedConnectInfo.ip,
  vmId: observedConnectInfo.vmId,
  vmUserName: observedConnectInfo.username,
}, {
  randomKey: '0x2f4bd52a',
  clientKey: 'f8ec01000d4c33479ff0b4e32f9cbcbd',
  traceId: '89d445d22658b6a6553f6cdedd39f518',
  spanId: '7ed90069beaa2181',
  serverKey: `0x${observedServerKeyPacket.keyInfo.key.toString(16)}`,
  tunnelId: '0x34db0787',
});
assert.strictEqual(offlineHandshakePlan.safe.sendsPackets, false);
assert.strictEqual(offlineHandshakePlan.localKey.datagram.length, observedControlPayload.length);
assert.strictEqual(offlineHandshakePlan.connectInfo.payloadLength, 0xdc);
assert.strictEqual(offlineHandshakePlan.connectInfo.usernamePresent, true);
const offlineConnectInfo = createConnectInfoDatagram({
  vmcPort: observedConnectInfo.port,
  vmcIp: observedConnectInfo.ip,
  vmId: observedConnectInfo.vmId,
  vmUserName: observedConnectInfo.username,
}, {
  randomKey: '0x2f4bd52a',
  serverKey: `0x${observedServerKeyPacket.keyInfo.key.toString(16)}`,
  tunnelId: '0x34db0787',
});
assert.strictEqual(parseZteCagDatagram(offlineConnectInfo.datagram).udpControl.header.controlWord, 0);

const zteReply = parseZteCagConnectReply(Buffer.concat([Buffer.from('c8000000', 'hex'), Buffer.alloc(32)]));
assert.strictEqual(zteReply.ok, true);
assert.strictEqual(zteReply.code, 200);

const head = encodeChuanyunHead({
  type: ChuanyunFrameType.DATA,
  payloadLength: 3,
  sessionId: 0x010203n,
  channelId: ChuanyunChannel.DISPLAY,
});
assert.strictEqual(head.length, CHUANYUN_HEAD_SIZE);
assert.strictEqual(head.toString('hex'), '010103000000000003020100000000000200000000000000');
assert.deepStrictEqual(decodeChuanyunHead(head), {
  version: 1,
  type: ChuanyunFrameType.DATA,
  payloadLength: 3,
  reserved: 0,
  sessionId: 0x010203n,
  channelId: 2n,
});

const frame = encodeChuanyunFrame({
  type: ChuanyunFrameType.DATA,
  sessionId: 7n,
  channelId: ChuanyunChannel.MAIN,
  payload: Buffer.from([0xaa, 0xbb]),
});
const decodedFrame = decodeChuanyunFrame(Buffer.concat([frame, Buffer.from([0xcc])]));
assert.strictEqual(decodedFrame.head.payloadLength, 2);
assert.deepStrictEqual([...decodedFrame.payload], [0xaa, 0xbb]);
assert.deepStrictEqual([...decodedFrame.rest], [0xcc]);

const mini = encodeMiniHeader(SpiceMessage.DISPLAY_INIT, 14);
assert.strictEqual(mini.toString('hex'), '65000e000000');

const miniCaps = encodeCapabilityWords([SpiceCommonCapability.MINI_HEADER]);
assert.strictEqual(miniCaps.toString('hex'), '08000000');
assert.deepStrictEqual(decodeCapabilityWords(miniCaps, 1).bits, [SpiceCommonCapability.MINI_HEADER]);

const linkHeader = encodeSpiceLinkHeader(18);
assert.strictEqual(linkHeader.toString('hex'), '52454451020000000200000012000000');
assert.deepStrictEqual(decodeSpiceLinkHeader(linkHeader), {
  magic: Buffer.from('REDQ', 'ascii'),
  majorVersion: 2,
  minorVersion: 2,
  size: 18,
});

const mainLink = encodeSpiceLinkMess({
  connectionId: 0,
  channelType: SpiceChannel.MAIN,
  channelId: 0,
});
const decodedMainLink = decodeSpiceLinkMess(Buffer.concat([mainLink, Buffer.from([0xcc])]));
assert.strictEqual(decodedMainLink.connectionId, 0);
assert.strictEqual(decodedMainLink.channelType, SpiceChannel.MAIN);
assert.strictEqual(decodedMainLink.channelId, 0);
assert.strictEqual(decodedMainLink.header.size, 22);
assert.deepStrictEqual(decodedMainLink.commonCaps.bits, [SpiceCommonCapability.MINI_HEADER]);
assert.deepStrictEqual([...decodedMainLink.rest], [0xcc]);

const displayLink = encodeSpiceLinkMess({
  connectionId: 0x11223344,
  channelType: SpiceChannel.DISPLAY,
  channelId: 0,
  commonCaps: miniCaps,
  channelCaps: encodeCapabilityWords([1, 33]),
});
const decodedDisplayLink = decodeSpiceLinkMess(displayLink);
assert.strictEqual(decodedDisplayLink.connectionId, 0x11223344);
assert.strictEqual(decodedDisplayLink.channelType, SpiceChannel.DISPLAY);
assert.deepStrictEqual(decodedDisplayLink.channelCaps.bits, [1, 33]);

const replyBody = Buffer.alloc(178 + 4);
replyBody.writeUInt32LE(0, 0);
Buffer.alloc(162, 0xab).copy(replyBody, 4);
replyBody.writeUInt32LE(1, 166);
replyBody.writeUInt32LE(0, 170);
replyBody.writeUInt32LE(178, 174);
miniCaps.copy(replyBody, 178);
const decodedReply = decodeSpiceLinkReply(Buffer.concat([encodeSpiceLinkHeader(replyBody.length), replyBody]));
assert.strictEqual(decodedReply.ok, true);
assert.strictEqual(decodedReply.pubkey.length, 162);
assert.strictEqual(decodedReply.pubkeyLength, 162);
assert.strictEqual(decodedReply.pubkey[0], 0xab);
assert.deepStrictEqual(decodedReply.commonCaps.bits, [SpiceCommonCapability.MINI_HEADER]);

const dynamicDerPubkey = Buffer.concat([
  Buffer.from('30820122', 'hex'),
  Buffer.alloc(290, 0xcd),
]);
const dynamicReplyBody = Buffer.concat([
  Buffer.alloc(4),
  dynamicDerPubkey,
  Buffer.from('0100000001000000112715273a010000cb05000009174856', 'hex'),
]);
const decodedDynamicReply = decodeSpiceLinkReply(Buffer.concat([encodeSpiceLinkHeader(dynamicReplyBody.length), dynamicReplyBody]));
assert.strictEqual(readDerObjectLength(dynamicDerPubkey), 294);
assert.strictEqual(decodedDynamicReply.pubkeyLength, 294);
assert.strictEqual(decodedDynamicReply.pubkey.toString('hex'), dynamicDerPubkey.toString('hex'));
assert.strictEqual(decodedDynamicReply.opaqueTail.length, 24);

assert.deepStrictEqual(decodeSpiceAuthResult(Buffer.from('00000000ff', 'hex')), {
  ok: true,
  code: 0,
  rest: Buffer.from('ff', 'hex'),
});

const displayInit = encodeDisplayInit();
const decodedDisplayInit = decodeMiniMessage(displayInit);
assert.strictEqual(decodedDisplayInit.header.type, SpiceMessage.DISPLAY_INIT);
assert.strictEqual(decodedDisplayInit.header.size, 14);
assert.strictEqual(decodedDisplayInit.payload.readUInt8(0), 1);
assert.strictEqual(decodedDisplayInit.payload.readBigInt64LE(1), 20n * 1024n * 1024n);
assert.strictEqual(decodedDisplayInit.payload.readUInt8(9), 1);
assert.strictEqual(decodedDisplayInit.payload.readUInt32LE(10), 8 * 1024 * 1024);

const setAckPayload = Buffer.alloc(8);
setAckPayload.writeUInt32LE(7, 0);
setAckPayload.writeUInt32LE(20, 4);
assert.deepStrictEqual(decodeSetAckPayload(setAckPayload), { generation: 7, window: 20 });
assert.strictEqual(encodeAckSync(7).toString('hex'), '06000400000007000000');
assert.strictEqual(encodeAck().toString('hex'), '070000000000');
assert.strictEqual(encodePong(Buffer.from('0102030405060708', 'hex')).toString('hex'), '0500080000000102030405060708');

const dataHeader = encodeDataHeader(SpiceMessage.SET_ACK, 8, { serial: 1n });
assert.strictEqual(dataHeader.toString('hex'), '010000000000000003000800000000000000');
assert.deepStrictEqual(decodeDataHeader(dataHeader), {
  serial: 1n,
  type: SpiceMessage.SET_ACK,
  size: 8,
  subList: 0,
});
const dataMessage = encodeDataMessage(SpiceMessage.SET_ACK, setAckPayload, { serial: 1n });
const decodedDataMessage = decodeDataMessage(Buffer.concat([dataMessage, Buffer.from([0xff])]));
assert.strictEqual(decodedDataMessage.header.type, SpiceMessage.SET_ACK);
assert.deepStrictEqual(decodeSetAckPayload(decodedDataMessage.payload), { generation: 7, window: 20 });
assert.deepStrictEqual([...decodedDataMessage.rest], [0xff]);

const observedMainExtInfo = Buffer.from(
  '1a009c001027010080020a0a00000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000065393138' +
  '37633636646166646666316338346162' +
  '32313332346165306438353500613161' +
  '32613233313530313137616232000001' +
  '0a01d902',
  'hex',
);
const observedDisplayExtInfo = Buffer.from(
  '1a009c001027030080020a0a00000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000000000000' +
  '00000000000000000000000065393138' +
  '37633636646166646666316338346162' +
  '32313332346165306438353500353663' +
  '65343733336465303336353637000002' +
  '0a02dd02',
  'hex',
);
const decodedMainExtInfo = decodeLocalSpiceExtInfo(observedMainExtInfo);
assert.strictEqual(decodedMainExtInfo.field00, 0x001a);
assert.strictEqual(decodedMainExtInfo.field02, 0x009c);
assert.strictEqual(decodedMainExtInfo.localPortHint, 0x2710);
assert.strictEqual(decodedMainExtInfo.channelClass, 1);
assert.strictEqual(decodedMainExtInfo.primaryId, 'e9187c66dafdff1c84ab21324ae0d855');
assert.strictEqual(decodedMainExtInfo.secondaryId, 'a1a2a23150117ab2');
assert.strictEqual(decodedMainExtInfo.field9eBe, 1);
assert.strictEqual(decodedMainExtInfo.fielda0Be, 0x0a01);
assert.strictEqual(decodedMainExtInfo.fielda2Le, 0x02d9);
const decodedDisplayExtInfo = decodeLocalSpiceExtInfo(observedDisplayExtInfo);
assert.strictEqual(decodedDisplayExtInfo.channelClass, 3);
assert.strictEqual(decodedDisplayExtInfo.secondaryId, '56ce4733de036567');
assert.strictEqual(decodedDisplayExtInfo.field9eBe, 2);
assert.strictEqual(decodedDisplayExtInfo.fielda0Be, 0x0a02);

const localClientHandshake = decodeLocalSpiceClientHandshake(Buffer.concat([observedMainExtInfo, mainLink]));
assert.strictEqual(localClientHandshake.redqOffset, 164);
assert.strictEqual(localClientHandshake.link.channelType, SpiceChannel.MAIN);

const observedDisplayClientData = Buffer.concat([
  Buffer.from('0a028000', 'hex'),
  Buffer.alloc(128),
  Buffer.from(
    '0a022600' +
    '010000000000000065001300000000000000000100004001000000000100fc5f000000000003',
    'hex',
  ),
]);
const decodedDisplayClientData = decodeLocalSpiceClientDataMessages(observedDisplayClientData);
assert.strictEqual(decodedDisplayClientData.authFrame.channelPrefix, 2);
assert.strictEqual(decodedDisplayClientData.authFrame.payloadLength, 128);
assert.strictEqual(decodedDisplayClientData.messages.length, 1);
assert.strictEqual(decodedDisplayClientData.messages[0].channelPrefix, 2);
assert.strictEqual(decodedDisplayClientData.messages[0].header.type, SpiceMessage.DISPLAY_INIT);
assert.strictEqual(decodedDisplayClientData.messages[0].header.size, 19);
assert.strictEqual(decodedDisplayClientData.messages[0].payload.toString('hex'), '000100004001000000000100fc5f0000000000');
assert.strictEqual(decodedDisplayClientData.messages[0].trailer.toString('hex'), '03');

const syntheticServerReply = Buffer.concat([
  Buffer.from([2]),
  encodeSpiceLinkHeader(replyBody.length),
  replyBody,
  Buffer.from('00000000', 'hex'),
  encodeDataMessage(SpiceMessage.SET_ACK, setAckPayload, { serial: 1n }),
]);
const decodedLocalServer = decodeLocalSpiceServerHandshake(syntheticServerReply);
assert.strictEqual(decodedLocalServer.channelPrefix, 2);
assert.strictEqual(decodedLocalServer.reply.pubkeyLength, 162);
const serverAuth = decodeSpiceAuthResult(decodedLocalServer.rest);
assert.strictEqual(serverAuth.ok, true);
assert.strictEqual(decodeDataMessage(serverAuth.rest).header.type, SpiceMessage.SET_ACK);

const observedDisplayServerData = Buffer.concat([
  Buffer.from('00000000', 'hex'),
  Buffer.from('010000000000000003000800000000000000000100000046000000', 'hex'),
  Buffer.from('02000000000000000300080000000000000000020000004600000003000000000000006c0000000000000000000004000000000000003a01140000000000000000000000000004000000030000200000000100000005000000000000006600000000000000000000', 'hex'),
  Buffer.from('060000000000000003000800000000000000000300000000000000', 'hex'),
]);
const decodedDisplayServerData = decodeLocalSpiceServerDataMessages(observedDisplayServerData);
assert.strictEqual(decodedDisplayServerData.authResult.ok, true);
assert.deepStrictEqual(
  decodedDisplayServerData.messages.map((msg) => Number(msg.header.serial)),
  [1, 2, 3, 4, 5, 6],
);
assert.deepStrictEqual(
  decodedDisplayServerData.messages.map((msg) => msg.header.type),
  [
    SpiceMessage.SET_ACK,
    SpiceMessage.SET_ACK,
    0x006c,
    SpiceMessage.SURFACE_CREATE,
    SpiceMessage.MARK,
    SpiceMessage.SET_ACK,
  ],
);
assert.deepStrictEqual(decodedDisplayServerData.messages.map((msg) => msg.paddingLength), [1, 1, 1, 1, 1, 1]);
assert.strictEqual(decodedDisplayServerData.messages[3].payload.length, 20);
assert.strictEqual(decodedDisplayServerData.rest.length, 0);
assert.strictEqual(decodedDisplayServerData.error, null);

let progress = createProtocolProgress();
progress = applyProtocolEvent(progress, ProtocolStage.DISPLAY_INIT_SENT);
progress = applyProtocolEvent(progress, ProtocolStage.SURFACE_CREATE_RECEIVED);
assert.strictEqual(isProtocolKeepaliveSuccess(progress), false);
progress = applyProtocolEvent(progress, ProtocolStage.DRAW_COPY_RECEIVED);
assert.strictEqual(isProtocolKeepaliveSuccess(progress), true);

const markOnlyProgress = applyProtocolEvent(
  applyProtocolEvent(createProtocolProgress(), ProtocolStage.DRAW_COPY_RECEIVED),
  ProtocolStage.MARK_RECEIVED,
);
assert.strictEqual(isProtocolKeepaliveSuccess(markOnlyProgress), false, 'DISPLAY_INIT is required before success');

console.log('protocol-codec tests passed');

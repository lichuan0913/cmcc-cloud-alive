#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const {
  createLocalKeyDatagram,
  parseZteCagDatagram,
} = require('../lib/protocol');

function usage() {
  console.error('Usage: node scripts/extract-cag-handshake.js <cag.pcap> [--from SEC.USEC] [--to SEC.USEC]');
  process.exit(2);
}

function parseArgs(argv) {
  const out = { _: [], from: null, to: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--from') {
      out.from = Number(argv[++i] || 0);
    } else if (arg === '--to') {
      out.to = Number(argv[++i] || 0);
    } else {
      out._.push(arg);
    }
  }
  return out;
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function packetTime(packet) {
  return `${packet.seconds}.${String(packet.micros).padStart(6, '0')}`;
}

function packetTimeNumber(packet) {
  return Number(packetTime(packet));
}

function inTimeWindow(packet, args) {
  const time = packetTimeNumber(packet);
  if (args.from !== null && time < args.from) return false;
  if (args.to !== null && time > args.to) return false;
  return true;
}

function parseClassicEthernetPcap(file) {
  const buffer = fs.readFileSync(file);
  if (buffer.length < 24) throw new Error('pcap file is too short');
  const magic = buffer.readUInt32LE(0);
  if (magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1) {
    throw new Error('only classic little-endian Ethernet pcap files are supported');
  }

  let offset = 24;
  const packets = [];
  while (offset + 16 <= buffer.length) {
    const seconds = buffer.readUInt32LE(offset);
    const micros = buffer.readUInt32LE(offset + 4);
    const capturedLength = buffer.readUInt32LE(offset + 8);
    const packetOffset = offset + 16;
    offset = packetOffset + capturedLength;
    if (capturedLength < 34) continue;
    if (buffer.readUInt16BE(packetOffset + 12) !== 0x0800) continue;

    const ipOffset = packetOffset + 14;
    const ipHeaderLength = (buffer[ipOffset] & 0x0f) * 4;
    const protocol = buffer[ipOffset + 9];
    if (protocol !== 17) continue;
    const sourceIp = [...buffer.subarray(ipOffset + 12, ipOffset + 16)].join('.');
    const destinationIp = [...buffer.subarray(ipOffset + 16, ipOffset + 20)].join('.');
    const l4Offset = ipOffset + ipHeaderLength;
    const udpLength = buffer.readUInt16BE(l4Offset + 4);
    packets.push({
      seconds,
      micros,
      sourceIp,
      destinationIp,
      sourcePort: buffer.readUInt16BE(l4Offset),
      destinationPort: buffer.readUInt16BE(l4Offset + 2),
      payload: buffer.subarray(l4Offset + 8, l4Offset + udpLength),
    });
  }
  return packets;
}

function firstRemoteHost(packets) {
  const counts = new Map();
  for (const packet of packets) {
    for (const ip of [packet.sourceIp, packet.destinationIp]) {
      if (ip.startsWith('127.')) continue;
      if (/^(10|172\.16|172\.17|172\.18|172\.19|172\.2\d|172\.3[01]|192\.168)\./.test(ip)) continue;
      counts.set(ip, (counts.get(ip) || 0) + 1);
    }
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || '';
}

function direction(packet, remoteHost) {
  if (remoteHost && packet.destinationIp === remoteHost) return 'client->cag';
  if (remoteHost && packet.sourceIp === remoteHost) return 'cag->client';
  return `${packet.sourceIp}:${packet.sourcePort}->${packet.destinationIp}:${packet.destinationPort}`;
}

function hex32(value) {
  return `0x${(Number(value) >>> 0).toString(16).padStart(8, '0')}`;
}

function summarizeUdpControl(packet, parsed, remoteHost) {
  const control = parsed.udpControl;
  const base = {
    time: packetTime(packet),
    direction: direction(packet, remoteHost),
    source: `${packet.sourceIp}:${packet.sourcePort}`,
    destination: `${packet.destinationIp}:${packet.destinationPort}`,
    payloadLength: packet.payload.length,
    payloadSha256: sha256Hex(packet.payload),
    type: control.header.type,
    typeName: control.header.typeName,
    sequence: control.header.sequence,
    routeIdHex: control.header.routeId.toString('hex'),
    tunnelIdHex: hex32(control.header.tunnelId),
    controlWord: control.header.controlWord,
    controlPayloadLength: control.payload.length,
  };

  if (control.ztecOpentelemetryKeyInfo) {
    const key = control.ztecOpentelemetryKeyInfo;
    base.randomKeyHex = hex32(key.key);
    base.clientKeyHex = key.clientKey.toString('hex');
    base.connectInfoLength = key.connectInfoLength;
    base.flagsHex = hex32(key.flags);
    base.baseFlags = key.flags & 0xffff;
    base.transportFlag = key.transportFlag;
    base.addressFamilyFlag = key.addressFamilyFlag;
    base.traceId = key.traceId;
    base.spanId = key.spanId;
  }
  if (control.ztecServerKeyInfo) {
    const key = control.ztecServerKeyInfo;
    base.serverKeyHex = hex32(key.key);
    base.serverKeyFlagsHex = hex32(key.flags);
    base.sdkAesFlagsHex = hex32(key.sdkAesFlags);
    base.dynamicTunnelWord0Hex = hex32(control.dynamicTunnelWord0);
  }
  if (control.connectReply) {
    base.connectReply = {
      ok: control.connectReply.ok,
      code: control.connectReply.code,
    };
  }

  return base;
}

function extractHandshake(file, args) {
  const packets = parseClassicEthernetPcap(file).filter((packet) => inTimeWindow(packet, args));
  const remoteHost = firstRemoteHost(packets);
  const events = [];

  for (const packet of packets) {
    if (!packet.payload.length) continue;
    const parsed = parseZteCagDatagram(packet.payload);
    if (!parsed.udpControl) continue;
    const type = parsed.udpControl.header.type;
    if (type === 0x06 || type === 0x07 || type === 0x08 || type === 0x09) {
      events.push(summarizeUdpControl(packet, parsed, remoteHost));
    }
  }

  const localKey = events.find((event) => event.type === 0x06 && event.randomKeyHex);
  const serverKey = events.find((event) => event.type === 0x07 && event.serverKeyHex);
  const connectInfo = events.find((event) => event.type === 0x08);
  const connectReply = events.find((event) => event.type === 0x09 && event.connectReply);

  let localKeyRebuild = null;
  if (localKey) {
    const rebuilt = createLocalKeyDatagram({
      randomKey: localKey.randomKeyHex,
      clientKey: localKey.clientKeyHex,
      baseFlags: localKey.baseFlags,
      transportFlag: localKey.transportFlag,
      addressFamilyFlag: localKey.addressFamilyFlag,
      sequence: localKey.sequence,
      traceId: localKey.traceId,
      spanId: localKey.spanId,
    });
    localKeyRebuild = {
      length: rebuilt.datagram.length,
      sha256: sha256Hex(rebuilt.datagram),
      matchesObserved: sha256Hex(rebuilt.datagram) === localKey.payloadSha256,
    };
  }

  return {
    file,
    packets: packets.length,
    remoteHost,
    events,
    handshake: {
      localKey,
      serverKey,
      connectInfo,
      connectReply,
    },
    localKeyRebuild,
    cagPlanArgs: localKey && serverKey ? {
      randomKey: localKey.randomKeyHex,
      clientKey: localKey.clientKeyHex,
      localKeySequence: localKey.sequence,
      traceId: localKey.traceId,
      spanId: localKey.spanId,
      serverKey: serverKey.serverKeyHex,
      tunnelId: serverKey.tunnelIdHex,
      connectInfoSequence: connectInfo?.sequence,
      connectInfoControlWord: connectInfo?.controlWord,
      aesFlags: '1',
    } : null,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const file = args._[0];
  if (!file) usage();
  console.log(JSON.stringify(extractHandshake(file, args), null, 2));
}

main();

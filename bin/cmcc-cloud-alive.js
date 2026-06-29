#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const {
  cachedCloudList,
  cloudStatus,
  FamilyApiError,
  getFirmAuth,
  heartbeat,
  importLegacyState,
  isHeartbeatAccepted,
  listClouds,
  loadState,
  maskFirmAuth,
  maskState,
  smsLogin,
  smsSend,
  summarizeFirmAuth,
  tokenCheck,
} = require('../lib/family-api');
const { createCagHandshakePlan, createProtocolProbeReport, probeProtocolRoute } = require('../lib/protocol');

function usage() {
  console.log(`Usage:
  cmcc-cloud-alive sms-send <phone>
  cmcc-cloud-alive sms-login <phone> <code>
  cmcc-cloud-alive list
  cmcc-cloud-alive list-cache
  cmcc-cloud-alive cloud-status [userServiceId]
  cmcc-cloud-alive firm-auth <userServiceId>
  cmcc-cloud-alive protocol-probe <userServiceId> [--tls-probe 1] [--timeout-ms 5000]
  cmcc-cloud-alive cag-plan <userServiceId> [--random-key HEX] [--server-key HEX] [--tunnel-id HEX] [--local-key-sequence N] [--connect-info-sequence N] [--connect-info-control-word N] [--show-hex 0]
  cmcc-cloud-alive heartbeat <userServiceId>
  cmcc-cloud-alive heartbeat-loop <userServiceId> [--interval-ms 30000] [--stop-on-error 0]
  cmcc-cloud-alive verify-http <userServiceId> [--duration-ms 120000] [--interval-ms 30000] [--wait-powered-ms 0] [--require-sleep-proof 0]
  cmcc-cloud-alive token-check
  cmcc-cloud-alive import-legacy-state
  cmcc-cloud-alive state
  cmcc-cloud-alive analyze-cag <pcap> [--limit N]
  cmcc-cloud-alive extract-cag-handshake <pcap> [--from SEC.USEC] [--to SEC.USEC]
  cmcc-cloud-alive analyze-loopback <pcap>
  cmcc-cloud-alive test

This project is the protocol-level implementation workspace. It does not start
the official SDK client.`);
}

function runNodeScript(script, args) {
  const scriptPath = path.join(__dirname, '..', 'scripts', script);
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    stdio: 'inherit',
  });
  process.exit(result.status ?? 1);
}

function printCloudList(list) {
  if (!list.length) {
    console.log('no cloud PC found');
    return;
  }
  list.forEach((item, i) => {
    console.log(`${i}: userServiceId=${item.userServiceId} vmName=${item.vmName || item.cloudPcName || ''} spuCode=${item.spuCode || ''} sku=${item.skuName || ''}`);
  });
}

function readOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  return args[index + 1] === undefined ? fallback : args[index + 1];
}

function formatTime(date = new Date()) {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatDuration(ms) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}小时${minutes}分${seconds}秒`;
  if (minutes > 0) return `${minutes}分${seconds}秒`;
  return `${seconds}秒`;
}

function errorSummary(err) {
  if (err instanceof FamilyApiError || err.name === 'FamilyApiError') {
    const code = err.code === undefined ? '' : ` code=${err.code}`;
    const businessCode = err.businessCode === undefined ? '' : ` businessCode=${err.businessCode}`;
    return `${err.kind || 'api'}${code}${businessCode} ${err.message}`.trim();
  }
  return err?.message || String(err);
}

async function resolveCachedUserServiceId(value) {
  if (value) return value;
  const cached = cachedCloudList();
  if (cached[0]?.userServiceId) return cached[0].userServiceId;
  const fresh = await listClouds();
  if (fresh[0]?.userServiceId) return fresh[0].userServiceId;
  throw new Error('no userServiceId found; run list first or pass one explicitly');
}

async function main(argv = process.argv.slice(2)) {
  const cmd = argv[0];
  const args = argv.slice(1);
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
    usage();
    return;
  }
  if (cmd === 'sms-send') {
    const response = await smsSend(args[0]);
    console.log(JSON.stringify(response, null, 2));
    return;
  }
  if (cmd === 'sms-login') {
    await smsLogin(args[0], args[1]);
    console.log('login ok');
    return;
  }
  if (cmd === 'list') {
    printCloudList(await listClouds());
    return;
  }
  if (cmd === 'list-cache') {
    printCloudList(cachedCloudList());
    return;
  }
  if (cmd === 'cloud-status') {
    const userServiceId = await resolveCachedUserServiceId(args[0]?.startsWith('--') ? '' : args[0]);
    console.log(JSON.stringify(await cloudStatus(userServiceId), null, 2));
    return;
  }
  if (cmd === 'firm-auth') {
    const userServiceId = await resolveCachedUserServiceId(args[0]?.startsWith('--') ? '' : args[0]);
    const auth = await getFirmAuth(userServiceId);
    const protocolReport = createProtocolProbeReport({ userServiceId, auth });
    console.log(JSON.stringify({
      userServiceId,
      summary: summarizeFirmAuth(auth),
      route: protocolReport.route,
      authMaterial: protocolReport.authMaterial,
      auth: maskFirmAuth(auth),
    }, null, 2));
    return;
  }
  if (cmd === 'protocol-probe') {
    const userServiceId = await resolveCachedUserServiceId(args[0]?.startsWith('--') ? '' : args[0]);
    const auth = await getFirmAuth(userServiceId);
    const tlsProbe = String(readOption(args, '--tls-probe', '1')) !== '0';
    const timeoutMs = Number(readOption(args, '--timeout-ms', 5000));
    const report = await probeProtocolRoute({ userServiceId, auth, tlsProbe, timeoutMs });
    console.log(JSON.stringify({
      ...report,
      authSummary: summarizeFirmAuth(auth),
      safe: {
        ...report.safe,
        sdkStarted: false,
        desktopConnectSent: false,
        spiceAuthSent: false,
      },
    }, null, 2));
    return;
  }
  if (cmd === 'cag-plan') {
    const userServiceId = await resolveCachedUserServiceId(args[0]?.startsWith('--') ? '' : args[0]);
    const auth = await getFirmAuth(userServiceId);
    const plan = createCagHandshakePlan(auth, {
      randomKey: readOption(args, '--random-key', undefined),
      clientKey: readOption(args, '--client-key', undefined),
      traceId: readOption(args, '--trace-id', undefined),
      spanId: readOption(args, '--span-id', undefined),
      localKeySequence: readOption(args, '--local-key-sequence', undefined),
      serverKey: readOption(args, '--server-key', undefined),
      tunnelId: readOption(args, '--tunnel-id', undefined),
      connectInfoSequence: readOption(args, '--connect-info-sequence', undefined),
      controlWord: readOption(args, '--connect-info-control-word', undefined),
      aesFlags: readOption(args, '--aes-flags', undefined),
      showHex: readOption(args, '--show-hex', '0'),
    });
    console.log(JSON.stringify({
      userServiceId,
      authSummary: summarizeFirmAuth(auth),
      plan,
    }, null, 2));
    return;
  }
  if (cmd === 'heartbeat') {
    const userServiceId = await resolveCachedUserServiceId(args[0]);
    const response = await heartbeat(userServiceId);
    console.log(JSON.stringify({
      ok: true,
      acceptedByClientLogic: isHeartbeatAccepted(response),
      userServiceId,
      code: response.code,
      msg: response.msg,
      businessCode: response.businessCode || '',
    }, null, 2));
    return;
  }
  if (cmd === 'heartbeat-loop') {
    const userServiceId = await resolveCachedUserServiceId(args[0]?.startsWith('--') ? '' : args[0]);
    const intervalMs = Math.max(5000, Number(readOption(args, '--interval-ms', 30000)));
    const stopOnError = String(readOption(args, '--stop-on-error', '0')) === '1';
    let stopped = false;
    process.on('SIGINT', () => { stopped = true; });
    process.on('SIGTERM', () => { stopped = true; });
    console.log(`heartbeat loop started: userServiceId=${userServiceId} intervalMs=${intervalMs} stopOnError=${stopOnError}`);
    let count = 0;
    let failures = 0;
    const loopStartedAt = Date.now();
    while (!stopped) {
      count++;
      const started = Date.now();
      try {
        const response = await heartbeat(userServiceId);
        failures = 0;
        console.log(`[${formatTime()}] [${count}] 保活响应: accepted=${isHeartbeatAccepted(response)} 持续=${formatDuration(Date.now() - loopStartedAt)} code=${response.code} msg=${response.msg || ''} businessCode=${response.businessCode || ''}`);
      } catch (err) {
        failures++;
        console.error(`[${formatTime()}] [${count}] 保活异常: failures=${failures} 持续=${formatDuration(Date.now() - loopStartedAt)} ${errorSummary(err)}`);
        if (err?.response) console.error(JSON.stringify(err.response));
        if (err instanceof FamilyApiError && (Number(err.code) === 4043 || Number(err.businessCode) === 4043)) {
          throw err;
        }
        if (stopOnError) throw err;
      }
      const elapsed = Date.now() - started;
      await wait(Math.max(0, intervalMs - elapsed));
    }
    console.log('heartbeat loop stopped');
    return;
  }
  if (cmd === 'token-check') {
    console.log(JSON.stringify(await tokenCheck(), null, 2));
    return;
  }
  if (cmd === 'import-legacy-state') {
    const state = importLegacyState();
    console.log(`imported legacy state to ${state._stateFile}`);
    return;
  }
  if (cmd === 'state') {
    const state = loadState();
    console.log(JSON.stringify({
      source: state._stateSource,
      stateFile: state._stateFile,
      state: maskState(state),
    }, null, 2));
    return;
  }
  if (cmd === 'analyze-cag') return runNodeScript('analyze-cag-transport.js', args);
  if (cmd === 'extract-cag-handshake') return runNodeScript('extract-cag-handshake.js', args);
  if (cmd === 'analyze-loopback') return runNodeScript('analyze-loopback-spice.js', args);
  if (cmd === 'verify-http') return runNodeScript('verify-http-heartbeat.js', args);
  if (cmd === 'test') return runNodeScript('../tests/protocol-codec.test.js', []);
  usage();
  process.exit(2);
}

main().catch((err) => {
  console.error(err.message);
  if (err.response) console.error(JSON.stringify(err.response, null, 2));
  process.exit(1);
});

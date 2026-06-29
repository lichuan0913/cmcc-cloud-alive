# cmcc-cloud-alive

Protocol-level keepalive research and implementation for China Mobile Cloud PC.

This is a new project. It is not the legacy SDK-wrapper keepalive that starts
`bootCypc` or `uSmartView_VDI_Client`.

## Source And Credit

This project is inspired by and cross-checks against the protocol analysis in:

<https://codming.com/posts/cmcc-cloud-computer-keepalive/>

The blog demonstrates that a real keepalive can be implemented at protocol
level by reaching the SPICE display channel, sending `DISPLAY_INIT`, observing
display surface traffic, and replying to keepalive messages. This repository
uses that success boundary, while also treating the observed Linux/ZTE
CAG/ZIME route as a first-class route.

## Goal

A successful protocol keepalive must:

- not start official SDK client binaries;
- authenticate the main and display channels;
- send `DISPLAY_INIT`;
- observe display surface/render signals such as `SURFACE_CREATE`, `DRAW_COPY`,
  or `MARK`;
- handle `SET_ACK`, `PING`, and `PONG` during the hold window.

SDK log lines such as `connectDesktop ret val: 0` are not considered protocol
success.

## Current Status

Implemented and tested:

- Family-edition SOHO API signing/RSA request support for SMS login, cloud
  list, token check, and the HTTP heartbeat candidate
  `/cc/cloudPc/heartbeat/v2`.
- SPICE REDQ link codecs, full data headers, `DISPLAY_INIT`, `SET_ACK`, ACK,
  and PONG helpers.
- Linux local GSpice/proxy loopback parser.
- Linux/ZTE CAG UDP `ZTEC` control parser.
- Dynamic CAG tunnel `word0` detection.
- Decoding for the observed CAG chain:
  `local_key -> server_key/tunnelId -> connect_info -> connect_reply 200`.
- Pcap analyzers for loopback SPICE and external CAG/ZIME traffic.

Not complete yet:

- standalone `keepalive` command that carries SPICE over CAG/ZIME without SDK;
- ZIME reliable UDP sequencing, ACK, retransmit, and close implementation;
- production sender for the Linux CAG route.
- long-duration proof that HTTP heartbeat alone prevents family cloud PC sleep
  while not occupying/kicking the normal official client session.

The current code is intentionally fail-closed around unproven auth/tunnel
sending paths.

## Usage

Run tests:

```bash
npm test
```

Login with the family-edition SOHO API:

```bash
node bin/cmcc-cloud-alive.js sms-send <phone>
node bin/cmcc-cloud-alive.js sms-login <phone> <code>
node bin/cmcc-cloud-alive.js list
node bin/cmcc-cloud-alive.js cloud-status <userServiceId>
node bin/cmcc-cloud-alive.js firm-auth <userServiceId>
node bin/cmcc-cloud-alive.js protocol-probe <userServiceId> --tls-probe 1
node bin/cmcc-cloud-alive.js cag-plan <userServiceId>
```

The SMS login flow is intentionally aligned with the previous `yidongyun`
family-edition SOHO API implementation. It is reused only to obtain and cache
the account login state needed by the protocol work; it is not the keepalive
mechanism.

If a legacy login already exists, import it instead of requesting another SMS
code:

```bash
node bin/cmcc-cloud-alive.js import-legacy-state
```

Run the HTTP heartbeat candidate once:

```bash
node bin/cmcc-cloud-alive.js heartbeat <userServiceId>
```

Run it continuously:

```bash
node bin/cmcc-cloud-alive.js heartbeat-loop <userServiceId> --interval-ms 30000
```

Generate a short verification report that checks heartbeat responses, official
client processes, CAG `8899` traffic, and cloud-PC status snapshots:

```bash
sudo node bin/cmcc-cloud-alive.js verify-http <userServiceId> \
  --duration-ms 120000 --interval-ms 30000
```

`verify-http` reports `httpPathOk` for the pure HTTP path and
`sleepPreventionProof` for the stronger claim that the VM stayed powered during
a long enough run. A powered-off VM can still return accepted heartbeat
responses, so `httpPathOk=true` alone is not final keepalive proof.

`firm-auth` calls the family `/cc/getFirmAuth/v1` endpoint and prints a redacted
protocol route summary. It does not start the official client or connect to
CAG/SPICE.

`protocol-probe` additionally performs a safe CAG TCP TLS handshake when
`--tls-probe 1` is used. It does not send desktop auth, SPICE auth, or SDK
socket commands.

`cag-plan` builds the CAG `local_key` and, when `--server-key` plus
`--tunnel-id` are supplied from a capture, `connect_info` datagram summaries
offline. It does not send packets. Hex output is hidden unless `--show-hex 1`
is explicitly passed.

Extract reusable CAG handshake parameters from a capture:

```bash
node bin/cmcc-cloud-alive.js extract-cag-handshake /path/to/cag.pcap
```

The output includes `cagPlanArgs`. These values can be passed back to
`cag-plan`, including `--local-key-sequence` and `--connect-info-sequence`, to
reproduce packet summaries from observed family-edition Linux CAG traffic. The
observed `connect_info` control word is also exposed as
`--connect-info-control-word` for capture-to-plan comparisons.

Use this as the final proof gate after the VM is already powered/running:

```bash
sudo node bin/cmcc-cloud-alive.js verify-http <userServiceId> \
  --duration-ms 3600000 \
  --interval-ms 30000 \
  --wait-powered-ms 600000 \
  --require-sleep-proof 1 \
  --report-file ./reports/http-proof.json
```

`--wait-powered-ms` is a precheck window. The proof timer starts only after the
cloud PC status becomes powered/running.

The heartbeat command is aligned to the family Linux client source: `4043`
(`YUN_OTHER_LOGIN`) is treated as a hard stop, while other JSON business codes
are recorded and the loop continues, matching the client heartbeat scheduler.
Transient network/API exceptions are logged and retried by default in
`heartbeat-loop`; pass `--stop-on-error 1` only for debugging.
On the current test account, `/cc/cloudPc/heartbeat/v2` returned:

```json
{
  "acceptedByClientLogic": true,
  "code": 4041,
  "msg": "当前云电脑处于解锁状态,且无密码",
  "businessCode": "90020129"
}
```

Analyze external CAG traffic:

```bash
node bin/cmcc-cloud-alive.js analyze-cag /path/to/cag.pcap --limit 80
```

Analyze local loopback SPICE traffic:

```bash
node bin/cmcc-cloud-alive.js analyze-loopback /path/to/loopback.pcap
```

## Docker

Build:

```bash
docker build -t cmcc-cloud-alive:local .
```

Run analyzer against a mounted capture:

```bash
docker run --rm -v "$PWD/captures:/captures:ro" \
  cmcc-cloud-alive:local \
  analyze-cag /captures/cag.pcap --limit 80
```

Compose:

```bash
docker compose run --rm cmcc-cloud-alive help
```

Login and run the HTTP heartbeat loop inside Docker:

```bash
docker compose run --rm cmcc-cloud-alive sms-send <phone>
docker compose run --rm cmcc-cloud-alive sms-login <phone> <code>
docker compose run --rm cmcc-cloud-alive list
docker compose run --rm cmcc-cloud-alive heartbeat-loop <userServiceId> --interval-ms 30000
```

For local migration testing, an existing legacy state file can be mounted
read-only instead of copying secrets into the image:

```bash
docker run --rm \
  -v /etc/yidongyun/state.json:/etc/yidongyun/state.json:ro \
  cmcc-cloud-alive:local heartbeat <userServiceId>
```

Run the loop persistently with Docker restart policy:

```bash
CMCC_USER_SERVICE_ID=<userServiceId> CMCC_INTERVAL_MS=30000 \
  docker compose --profile loop up -d cmcc-cloud-alive-loop

docker compose logs -f cmcc-cloud-alive-loop
docker compose --profile loop stop cmcc-cloud-alive-loop
```

## Development Notes

Keep the protocol project separate from legacy SDK-wrapper implementations.
Official client binaries may be used only as a research oracle for captures and
plaintext comparison. Production protocol mode must replace them with native
protocol code.

See [docs/protocol-keepalive.md](docs/protocol-keepalive.md) for the current
protocol map, capture evidence, implementation plan, and unresolved boundaries.

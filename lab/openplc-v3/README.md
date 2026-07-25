# OpenPLC v3 local lab

This compose project builds archived official
[`thiagoralves/OpenPLC_v3`](https://github.com/thiagoralves/OpenPLC_v3) commit
`b5d41356dab4aeadca0dd7ca64ba542f870b595d` and binds it to loopback only. Defaults avoid the
standard ports so it can coexist with another local lab.

```bash
docker compose -f lab/openplc-v3/compose.yaml build
docker compose -f lab/openplc-v3/compose.yaml up -d
curl -I http://127.0.0.1:18080/login
lab/openplc-v3/start-runtime.sh

plcfp scan 127.0.0.1 \
  --profile standard \
  --max-layer 4 \
  --modbus-port 1502 \
  --v3-http-port 18080 \
  --enip-port 14418 \
  --output openplc-v3-report.json \
  --no-raw

docker compose -f lab/openplc-v3/compose.yaml down
```

Use `OPENPLC_V3_MODBUS_PORT`, `OPENPLC_V3_HTTP_PORT`, and `OPENPLC_V3_ENIP_PORT` to change the host
mappings. Do not expose the intentionally obsolete v3 management UI beyond loopback or an isolated
lab network.

`start-runtime.sh` waits for the UI, signs in with the lab defaults `openplc/openplc`, invokes the
official `/start_plc` route, and prints the runtime log. Override credentials with
`OPENPLC_V3_USERNAME` and `OPENPLC_V3_PASSWORD`.

## Verified result

The command above was executed against the pinned image on 2026-07-25. The complete compact result
is in [`verified-result.json`](verified-result.json). Important observations:

- `major=v3`, `lifecycle=end-of-life`, `confidence=0.896`.
- No fabricated semver; the login release marker produced `epoch≈2025-Q4`.
- FC43 returned exception `01`, all unit IDs `0/1/247/255` responded, and the read-only function
  bitmap was `0x1e`.
- Address maxima were coils `8184`, discrete inputs `8184`, input registers `1023`, and holding
  registers `8191`.
- ENIP `ListIdentity` timed out while `RegisterSession` succeeded. Both the negative and positive
  observations remain in the evidence record.

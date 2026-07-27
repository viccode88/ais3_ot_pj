# Security policy

Use only on systems you own or are explicitly authorized to test in an isolated laboratory. Do not open a
public issue containing a new vulnerability or sensitive packet capture; contact the maintainers privately.
The default target policy rejects public addresses. The high-level `write` command does not transmit
writes, but the expert-level raw `send` command can transmit any supplied ADU, including write
functions; operators must decode and authorize raw payloads themselves. Operators remain responsible
for physical/process safety.

Port numbers are service hints, not proof. The scan-to-fuzz handoff only accepts an open Modbus/TCP
endpoint confirmed by an application-layer response, rechecks the report's resolved address against the
private-target policy, and still requires `--execute` before sending fuzz cases. The fuzzer serves
reliability testing of fully virtual lab targets, so the transport boundary deliberately does not
restrict function codes or MBAP framing: write functions, unknown operations, concatenated ADUs and
oversized payloads are transmitted as generated. Only an empty payload is blocked. This means fuzz
and replay targets must be disposable virtual environments, never production equipment. Executing
from a scan report first performs one correlated read-only FC03 preflight using the selected unit ID
and waits one configured fuzz interval before the first case. The raw `send` command likewise
transmits any supplied ADU.

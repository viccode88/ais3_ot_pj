# Security policy

Use only on systems you own or are explicitly authorized to test in an isolated laboratory. Do not open a
public issue containing a new vulnerability or sensitive packet capture; contact the maintainers privately.
The default target policy rejects public addresses. The high-level `write` command does not transmit
writes, but the expert-level raw `send` command can transmit any supplied ADU, including write
functions; operators must decode and authorize raw payloads themselves. Operators remain responsible
for physical/process safety.

Port numbers are service hints, not proof. The scan-to-fuzz handoff only accepts an open Modbus/TCP
endpoint confirmed by an application-layer response, rechecks the report's resolved address against the
private-target policy, and still requires `--execute` before sending fuzz cases. Mutated payloads are
checked again at the transport boundary; non-read-only function codes are recorded as blocked and are
not transmitted. The boundary also requires exactly one complete MBAP ADU and permits FC43 only for
MEI 0x0E Read Device Identification, preventing concatenated-ADU and multiplexed-function write
bypasses. Executing from a scan report first performs one correlated read-only FC03 preflight using
the selected unit ID and waits one configured fuzz interval before the first case. These fuzz/replay
safety gates do not apply to the raw `send` command.

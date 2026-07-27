# Architecture

`protocol` owns pure MBAP/PDU encoding and best-effort decoding. `transport` owns I/O and framing.
`fuzzing` generates deterministic cases and invokes an injected transport boundary; strategies never
open sockets themselves. `safety` resolves and validates a single target before I/O. `cli` only adapts
arguments/output. `plugins` discovers entry points, while `regression` keeps patch verification separate
from generic fuzzing. Future RTU, ASCII, TLS and gateway transports implement the `Transport` contract.

`plcfp.port_services` converts low-level TCP/protocol observations into deterministic `PortFinding`
records. PLC relevance and protocol confirmation are intentionally separate: a well-known port is only
a hint until an application probe succeeds. `modbus_cli.workflow` is the one-way integration boundary
from a JSON scan report to fuzzing. It revalidates the resolved address, scan-completeness marker and
bound protocol-valid observation, accepts only one open/confirmed/fuzz-eligible Modbus/TCP endpoint,
and performs a read-only endpoint preflight before report-driven execution; `plcfp` never imports the
fuzzer.

The fuzzer serves reliability testing of fully virtual lab targets, so the final transmit boundary
in `fuzzing.execute_cases` deliberately does not enforce read-only function codes or well-formed
MBAP framing: writes, unknown operations, malformed frames, concatenated requests and oversized
payloads all reach `TCPTransport`. Only an empty payload is recorded as `blocked-by-safety-policy`.
The `huge-payload` strategy builds the legacy malformed FC16 oversized ADU; it is a fuzz capability,
not part of any vulnerability case.

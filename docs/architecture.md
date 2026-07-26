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

At the final transmit boundary, `fuzzing.execute_cases` applies an explicit read-only function-code
allowlist and single-complete-ADU framing check to the mutated payload. FC43 is restricted to MEI 0x0E.
A generated case that became a write, unknown operation, malformed frame or concatenated request
remains in the report as `blocked-by-safety-policy` and never reaches `TCPTransport`.

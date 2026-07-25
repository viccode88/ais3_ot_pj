# Architecture

`protocol` owns pure MBAP/PDU encoding and best-effort decoding. `transport` owns I/O and framing.
`fuzzing` generates deterministic cases and invokes an injected transport boundary; strategies never
open sockets themselves. `safety` resolves and validates a single target before I/O. `cli` only adapts
arguments/output. `plugins` discovers entry points, while `regression` keeps patch verification separate
from generic fuzzing. Future RTU, ASCII, TLS and gateway transports implement the `Transport` contract.

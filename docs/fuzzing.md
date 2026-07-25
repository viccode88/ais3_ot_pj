# Fuzzing

Nine deterministic strategies cover field boundaries, bit/byte flips, MBAP length, function code,
transaction, unit ID, semantic inconsistency and random replacement. Generation is offline by default;
`--execute` explicitly enables bounded transmission. A timeout is classified conservatively as possible
service degradation, never as a crash or CVE. Re-run cases and a user-selected valid health check before
drawing conclusions. Current minimization is structural and must be replay-verified by the operator.

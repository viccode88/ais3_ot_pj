# Changelog

## Unreleased

- Show each executed fuzz case's decoded request and target-response packet types in the terminal.
- Add complete command syntax, parameter tables, examples, and side-effect notes to the CLI manual.
- Add PLC/ICS service-aware port findings, high-relevance markers, and text/CSV/SARIF port output.
- Integrate active scanning into `modbus-cli` and allow fuzz target selection from a confirmed scan report.
- Block mutated write/unknown function codes at the fuzz transport boundary.
- Correlate protocol responses to requests, distinguish unscanned ports, and reject echo-based service confirmation.
- Block concatenated ADUs and unsafe FC43 MEI subtypes; rate-limit replay and preflight report-driven execution.
- Add a complete PLC port-scan to controlled-fuzz guide with copyable workflows, field reference, safety boundaries, and troubleshooting.

## 0.2.0

- Replaced the single script with a safety-oriented protocol, transport, fuzz, plugin and regression framework.

# Plugin development

Publish an object with `name` and `api_version`, then register it without changing core code:

```toml
[project.entry-points."modbus_cli.plugins"]
example = "example_plugin:plugin"
```

Use `modbus-cli plugins list` and `modbus-cli plugins validate example`. Plugins must avoid global mutable
state, document safety effects, validate inputs, and use core transport/safety boundaries for network I/O.

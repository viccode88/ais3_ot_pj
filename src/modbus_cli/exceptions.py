"""Public exception hierarchy."""


class ModbusCLIError(Exception):
    """Base class for expected user-facing failures."""


class ConfigurationError(ModbusCLIError):
    """Configuration is invalid."""


class PacketEncodingError(ModbusCLIError):
    """A packet cannot be encoded."""


class PacketDecodingError(ModbusCLIError):
    """A packet cannot be decoded at all."""


class TransportError(ModbusCLIError):
    """Transport operation failed."""


class SafetyPolicyError(ModbusCLIError):
    """A safety policy rejected an operation."""


class PluginError(ModbusCLIError):
    """Plugin discovery or validation failed."""

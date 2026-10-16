"""
Custom exception hierarchy for the Network Security Toolkit.

All toolkit exceptions inherit from NetworkToolkitError so callers
can catch the entire family with a single except clause when needed.
"""
from __future__ import annotations


class NetworkToolkitError(Exception):
    """Base exception for all toolkit errors."""


class ConfigurationError(NetworkToolkitError):
    """Raised when a configuration file is missing, malformed, or contains invalid values."""


class InterfaceError(NetworkToolkitError):
    """Raised when a requested network interface cannot be opened or does not exist."""


class CaptureError(NetworkToolkitError):
    """Raised when the packet capture engine encounters a fatal error."""


class InsufficientPermissionsError(NetworkToolkitError):
    """
    Raised when the process lacks the OS-level privileges required for raw socket access.
    On Linux and macOS this typically means the process must run as root (uid 0).
    """


class ARPDetectionError(NetworkToolkitError):
    """Raised when the ARP spoofing detector encounters a fatal, unrecoverable error."""


class AnalysisError(NetworkToolkitError):
    """Raised when the traffic analysis engine cannot process a packet or packet stream."""

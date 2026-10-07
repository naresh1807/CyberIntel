"""Safe, structured operation errors without server bodies or credential URLs."""
import dns.exception
import httpx

from cyberintel.models import ValidationError
from .engines import ToolError


def operation_error(exc):
    if isinstance(exc, ToolError):
        return exc.code, str(exc)
    if isinstance(exc, (TimeoutError, httpx.TimeoutException, dns.exception.Timeout)):
        return "timeout", "Operation timed out."
    if isinstance(exc, PermissionError):
        return "permission_denied", "Check local file/executable permissions."
    if isinstance(exc, ValidationError):
        # These are application-authored messages. Only scope blocks include
        # the validated host; arbitrary exception payloads are never logged.
        if str(exc).startswith("OUT OF SCOPE:") or "explicitly excluded" in str(exc):
            return "scope_blocked", str(exc)
        if "cancel" in str(exc).lower():
            return "cancelled", "Operation cancelled."
        if "budget" in str(exc).lower() or "limit" in str(exc).lower():
            return "resource_limit", "Operation exceeded its configured resource budget."
        return "invalid_input", "Validation failed; check the selected inputs and configuration."
    if isinstance(exc, (httpx.HTTPError, OSError)):
        return "network_or_io_failure", type(exc).__name__ + ": connection or local I/O failed."
    return "parser_or_operation_failure", type(exc).__name__ + ": operation failed."

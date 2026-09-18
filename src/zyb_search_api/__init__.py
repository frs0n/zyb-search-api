"""Pure-Python client and HTTP API for the Zyb 14.53.0 image-search protocol."""

from .client import ClientError, search, search_bytes

__all__ = ["ClientError", "search", "search_bytes"]
__version__ = "1.0.0"

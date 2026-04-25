from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .server import main

__all__ = ["main"]

try:
    __version__ = _pkg_version("mcp-supervisor")
except PackageNotFoundError:
    __version__ = "0.0.0+local"

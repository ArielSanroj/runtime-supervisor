from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .client import Client, Decision, ReviewCase, SupervisorError

__all__ = ["Client", "Decision", "ReviewCase", "SupervisorError"]

try:
    __version__ = _pkg_version("supervisor-client")
except PackageNotFoundError:
    __version__ = "0.0.0+local"

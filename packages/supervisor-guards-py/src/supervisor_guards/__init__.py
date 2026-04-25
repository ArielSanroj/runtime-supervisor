from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .config import configure, get_client
from .context import observe, observing
from .core import guarded, supervised, supervised_async
from .errors import SupervisorBlocked, SupervisorReviewPending

__all__ = [
    "configure",
    "get_client",
    "supervised",
    "supervised_async",
    "guarded",
    "observe",
    "observing",
    "SupervisorBlocked",
    "SupervisorReviewPending",
]

try:
    __version__ = _pkg_version("supervisor-guards")
except PackageNotFoundError:
    __version__ = "0.0.0+local"

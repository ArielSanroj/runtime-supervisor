from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .findings import Confidence, Finding

__all__ = ["Finding", "Confidence"]

try:
    __version__ = _pkg_version("supervisor-discover")
except PackageNotFoundError:
    # Editable / source-only checkout without a wheel installed.
    __version__ = "0.0.0+local"

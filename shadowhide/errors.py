"""Errors intended to be presented clearly by the command-line interface."""


class ShadowHideError(Exception):
    """Base class for expected application errors."""


class InputError(ShadowHideError):
    """An input file or option is invalid or unsupported."""


class CapacityError(ShadowHideError):
    """The image cannot contain the requested payload."""


class PayloadError(ShadowHideError):
    """An embedded ShadowHide payload is missing, malformed, or corrupted."""


class OutputError(ShadowHideError):
    """An output path cannot safely be written."""

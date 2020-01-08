class UtilError(Exception):
    """Generic exception for nebula_utils"""


class UtilWrapperError(UtilError):
    """Wrapper exception for nebula_utils"""
    def __init__(self, msg, original_exception):
        super(UtilWrapperError, self).__init__(('{0}: {1}'.format(msg, original_exception)))
        self.original_exception = original_exception


class SuAuthenticationError(UtilError):
    """Raised when the a remote su command fails authentication."""


class RemoteIOError(IOError):
    """Raised when an IO error is encountered at the remote side of an ssh command session."""

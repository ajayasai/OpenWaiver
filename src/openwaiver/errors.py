class OpenWaiverError(ValueError):
    """Expected domain error, safe to show to a local authorized operator."""


class Conflict(OpenWaiverError):
    pass


class Forbidden(OpenWaiverError):
    pass


class NotFound(OpenWaiverError):
    pass


class IntegrityError(OpenWaiverError):
    pass

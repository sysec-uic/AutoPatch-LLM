from enum import Enum


class PatchResponseStatus(Enum):
    """
    Enum class for patch response status codes.
    """

    SUCCESS = 200
    MODEL_ROUTE_NOT_FOUND = 404
    MODEL_PROVIDER_NOT_FOUND = 404
    OUT_OF_QUOTA = 500
    PARTIAL_SUCCESS = 207
    FAILURE = 500
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    BAD_REQUEST = 400
    CONFLICT = 409
    INTERNAL_SERVER_ERROR = 500

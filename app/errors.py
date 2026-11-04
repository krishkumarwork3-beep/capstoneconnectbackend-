"""Errors are returned as `{"message": "..."}`: the frontend shows `message` as is.

The rule messages are the exact strings the UI (and its mock store) uses, so the same wording
appears whichever backend is in use.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

RULE_ERRORS = {
    "already_in_group": "You must leave your current group first",
    "group_full": "Group Full",
    "max_invites": "Max Invites",
    "lead_only": "Lead Only",
    "no_group": "No Group",
    "in_group": "In Group",
}


class AppError(Exception):
    def __init__(self, message: str, status: int = 400, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.headers = headers


def not_found(what: str) -> AppError:
    return AppError(f"{what} not found", 404)


def rule(key: str, status: int = 409) -> AppError:
    return AppError(RULE_ERRORS[key], status)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError):
        return JSONResponse({"message": exc.message}, status_code=exc.status, headers=exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse({"message": message}, status_code=exc.status_code)

    @app.exception_handler(IntegrityError)
    async def _conflict(_: Request, exc: IntegrityError):
        # Two requests changed the same thing at once (a student joining two groups, a phone
        # number taken in between): the database refused one of them.
        return JSONResponse({"message": "That changed while you were working on it. Refresh and try again."}, status_code=409)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(part) for part in first.get("loc", [])[1:])
        detail = first.get("msg", "Invalid request")
        message = f"{field}: {detail}" if field else detail
        return JSONResponse({"message": message}, status_code=422)

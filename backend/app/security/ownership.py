from typing import Any
from fastapi import HTTPException

FORBIDDEN_DETAIL = "You do not have permission to access this resource."


def owned_or_forbidden(record: Any, current_user: Any, owner_field: str = "user_id") -> Any:
    """Return ``record`` only when it belongs to ``current_user``.

    A missing record and a record owned by somebody else both raise the same
    403 response so that a caller can never tell whether another user's private
    resource exists (IDOR / object-reference protection).
    """
    if record is None or getattr(record, owner_field, None) != current_user.id:
        raise HTTPException(status_code=403, detail=FORBIDDEN_DETAIL)
    return record


def job_owned_or_forbidden(job: Any, current_user: Any, owner_field: str = "user_id") -> Any:
    """Same as :func:`owned_or_forbidden` but for plain dict records."""
    if job is None or job.get(owner_field) != current_user.id:
        raise HTTPException(status_code=403, detail=FORBIDDEN_DETAIL)
    return job

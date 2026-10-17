"""Step 6: human oversight - approval queue with separation of duties.

An approval is bound to a digest of the request. Changing the payload after
submission invalidates it. Pending and approved-but-unreleased approvals expire.
"""
from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from .audit import AuditLog
from .types import ActionRequest, now

DEFAULT_APPROVAL_TTL = timedelta(hours=24)


def request_digest(req: ActionRequest) -> str:
    """Hash the action the human is being asked to approve.

    Session id is attribution, not part of the action, so it is left out.
    """
    payload = {
        "agent_id": req.agent_id,
        "tool": req.tool,
        "action": req.action,
        "params": _canon(req.params),
        "data_classes": sorted(req.data_classes),
        "on_behalf_of": req.on_behalf_of,
        "peer_agent": req.peer_agent,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _canon(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canon(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        canon = [_canon(v) for v in value]
        return sorted(canon, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    return value


@dataclass
class PendingApproval:
    approval_id: str
    request: ActionRequest
    reason: str
    approver: str
    digest: str
    expires_at: datetime
    status: str = "pending"          # pending | approved | rejected | executed | expired
    decided_by: str | None = None


class ApprovalQueue:
    def __init__(self, audit: AuditLog, extra: Callable[[], dict[str, Any]] | None = None):
        self._items: dict[str, PendingApproval] = {}
        self._audit = audit
        self._extra = extra or (lambda: {})

    def _record(self, event: str, **fields: Any) -> None:
        self._audit.record(event, **{**self._extra(), **fields})

    def submit(self, req: ActionRequest, reason: str, approver: str,
               ttl: timedelta | None = None) -> str:
        aid = uuid.uuid4().hex[:10]
        stored = copy.deepcopy(req)
        digest = request_digest(stored)
        expires_at = now() + (ttl if ttl is not None else DEFAULT_APPROVAL_TTL)
        self._items[aid] = PendingApproval(aid, stored, reason, approver, digest, expires_at)
        self._record("approval_requested", approval_id=aid, agent=stored.agent_id,
                     tool=stored.tool, action=stored.action, params=stored.params,
                     approver=approver, digest=digest, expires_at=expires_at)
        return aid

    def decide(self, approval_id: str, by: str, approve: bool) -> PendingApproval:
        item = self._items[approval_id]
        if item.status != "pending":
            raise ValueError("already decided")
        stale = self._expire_if_needed(item)
        if stale:
            raise ValueError(stale)
        if by != item.approver:
            raise PermissionError(f"{by} is not the designated approver ({item.approver})")
        if by == item.request.on_behalf_of:
            raise PermissionError("separation of duties: requester cannot approve their own request")
        item.status = "approved" if approve else "rejected"
        item.decided_by = by
        self._record("approval_decided", approval_id=approval_id, by=by, status=item.status,
                     digest=item.digest)
        return item

    def get(self, approval_id: str) -> PendingApproval | None:
        return self._items.get(approval_id)

    def is_approved(self, approval_id: str) -> bool:
        item = self._items.get(approval_id)
        if item is None or item.status != "approved":
            return False
        if item.expires_at is not None and now() > item.expires_at:
            return False
        if request_digest(item.request) != item.digest:
            return False
        return True

    def stale_reason(self, item: PendingApproval) -> str | None:
        """Digest or expiry problem, or None when the bound request is still current."""
        if request_digest(item.request) != item.digest:
            return "approval is not bound to the current request"
        return self._expire_if_needed(item)

    def consume(self, approval_id: str) -> PendingApproval:
        """Single use: an approval releases its action once, then can never be reused."""
        item = self._items.get(approval_id)
        if item is None or item.status != "approved":
            raise ValueError("no unused approval with that id")
        stale = self.stale_reason(item)
        if stale:
            raise ValueError(stale)
        item.status = "executed"
        self._record("approval_consumed", approval_id=approval_id, digest=item.digest)
        return item

    def _expire_if_needed(self, item: PendingApproval) -> str | None:
        if item.expires_at is None or now() <= item.expires_at:
            return None
        if item.status in ("pending", "approved"):
            item.status = "expired"
            self._record("approval_expired", approval_id=item.approval_id, digest=item.digest)
        return "approval expired"

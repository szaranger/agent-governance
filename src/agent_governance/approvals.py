"""Step 6: human oversight - approval queue with separation of duties."""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from .audit import AuditLog
from .types import ActionRequest


@dataclass
class PendingApproval:
    approval_id: str
    request: ActionRequest
    reason: str
    approver: str
    status: str = "pending"          # pending | approved | rejected | executed
    decided_by: str | None = None


class ApprovalQueue:
    def __init__(self, audit: AuditLog):
        self._items: dict[str, PendingApproval] = {}
        self._audit = audit

    def submit(self, req: ActionRequest, reason: str, approver: str) -> str:
        aid = uuid.uuid4().hex[:10]
        self._items[aid] = PendingApproval(aid, req, reason, approver)
        self._audit.record("approval_requested", approval_id=aid, agent=req.agent_id,
                           tool=req.tool, action=req.action, params=req.params, approver=approver)
        return aid

    def decide(self, approval_id: str, by: str, approve: bool) -> PendingApproval:
        item = self._items[approval_id]
        if item.status != "pending":
            raise ValueError("already decided")
        if by != item.approver:
            raise PermissionError(f"{by} is not the designated approver ({item.approver})")
        if by == item.request.on_behalf_of:
            raise PermissionError("separation of duties: requester cannot approve their own request")
        item.status = "approved" if approve else "rejected"
        item.decided_by = by
        self._audit.record("approval_decided", approval_id=approval_id, by=by, status=item.status)
        return item

    def get(self, approval_id: str) -> PendingApproval | None:
        return self._items.get(approval_id)

    def is_approved(self, approval_id: str) -> bool:
        return self._items.get(approval_id, None) is not None and self._items[approval_id].status == "approved"

    def consume(self, approval_id: str) -> PendingApproval:
        """Single use: an approval releases its action once, then can never be reused."""
        item = self._items.get(approval_id)
        if item is None or item.status != "approved":
            raise ValueError("no unused approval with that id")
        item.status = "executed"
        self._audit.record("approval_consumed", approval_id=approval_id)
        return item
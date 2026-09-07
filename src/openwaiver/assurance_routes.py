"""Authenticated, read-only release evaluation. Trust and contract approvals are server-owned."""
import os
from pathlib import Path

from fastapi import Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import Field

from .assurance import ReleaseContract, capture_inventory, evaluate_contract
from .execution import ExecutionReceipt, read_trust
from .models import Model, Principal


class ReleaseRequest(Model):
    contract: ReleaseContract
    receipts: list[ExecutionReceipt] = Field(default_factory=list, max_length=1000)


def register_assurance_routes(app, service, principal):
    @app.get("/releases")
    def workspace():
        return FileResponse(Path(__file__).parent / "static" / "releases.html")

    @app.post("/api/release-assurance/evaluate")
    def evaluate(body: ReleaseRequest, actor: Principal = Depends(principal)):
        service.project(actor, body.contract.manifest.project)
        path = os.environ.get("OPENWAIVER_RELEASE_TRUST_FILE")
        if not path:
            raise HTTPException(503, "release trust has not been provisioned by the operator")
        try:
            trust = read_trust(Path(path))
        except Exception:
            raise HTTPException(503, "release trust unavailable") from None
        inventory = capture_inventory(service, body.contract, actor)
        return evaluate_contract(body.contract, **inventory, receipts=body.receipts, trust=trust)

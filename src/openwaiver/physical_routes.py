"""Read-only physical evidence routes use the existing project authorization boundary."""
from pathlib import Path
from fastapi import Depends
from fastapi.responses import FileResponse

from .models import Principal
from .physical import compare_physical, neighborhood_view


def register_physical_routes(app, service, principal):
    @app.get("/physical")
    def workspace():
        return FileResponse(Path(__file__).parent / "static" / "physical.html")

    @app.get("/api/physical/compare/{before}/{after}")
    def compare(before: str, after: str, actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            service.store.verify(conn)
            return compare_physical(service.read(conn, "runs", before, actor),
                                    service.read(conn, "runs", after, actor))

    @app.get("/api/runs/{id}/physical/{occurrence}")
    def inspect(id: str, occurrence: str, actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            service.store.verify(conn)
            return neighborhood_view(service.read(conn, "runs", id, actor), occurrence)

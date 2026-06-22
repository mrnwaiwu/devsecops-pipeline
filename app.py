"""
Sample FastAPI app used to demonstrate the DevSecOps pipeline.
Intentionally simple — the pipeline scans this on every push.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os

app = FastAPI(
    title="DevSecOps Demo App",
    description="Sample app scanned by the security pipeline",
    version="1.0.0",
)


class HealthResponse(BaseModel):
    status: str
    version: str


class ReadinessResponse(BaseModel):
    status: str
    checks: dict


@app.get("/health", response_model=HealthResponse)
def health_check():
    """Liveness endpoint."""
    return {"status": "ok", "version": "1.0.0"}


@app.get("/ready", response_model=ReadinessResponse)
def readiness_check():
    """Readiness endpoint - confirms the app can serve traffic."""
    return {"status": "ready", "checks": {"app": "ok"}}


@app.get("/")
def root():
    """Root endpoint."""
    return {"message": "DevSecOps pipeline demo"}

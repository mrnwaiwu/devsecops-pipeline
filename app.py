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


@app.get("/health", response_model=HealthResponse)
def health_check():
    """Liveness endpoint."""
    return {"status": "ok", "version": "1.0.0"}


@app.get("/")
def root():
    """Root endpoint."""
    return {"message": "DevSecOps pipeline demo"}

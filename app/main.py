"""ChainLens OSINT API.

A small FastAPI service that exposes the analyzer over HTTP and serves the
single-page analyst console. Run with:

    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import analyzer, detect
from .providers import http

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await http.close_client()


app = FastAPI(
    title="ChainLens OSINT",
    version="1.0.0",
    description="Blockchain and network open-source intelligence for a single target.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=256, description="Address, ENS name, IP or hostname")


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": app.version}


@app.post("/api/detect")
async def detect_target(payload: SearchRequest) -> dict:
    target = detect.detect(payload.query)
    return {
        "input": target.raw,
        "kind": target.kind,
        "chain": target.chain,
        "normalized": target.normalized,
        "notes": target.notes,
    }


@app.post("/api/analyze")
async def analyze_target(payload: SearchRequest) -> dict:
    try:
        return await analyzer.analyze(payload.query)
    except Exception as exc:  # noqa: BLE001 - surface provider failures cleanly
        raise HTTPException(status_code=502, detail=f"Analysis failed: {exc}") from exc


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

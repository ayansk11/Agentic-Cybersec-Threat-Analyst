"""FastAPI REST + SSE streaming endpoints."""

import asyncio
import json
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from backend.agents.graph import graph
from backend.api.auth import CurrentUser, get_current_user
from backend.api.rate_limit import limiter
from backend.api.schemas import (
    AnalysisHistoryItem,
    AnalysisHistoryResponse,
    AnalysisRequest,
    AnalysisResponse,
    CVEResponse,
    DashboardStats,
    FeedItem,
    FeedResponse,
    HealthResponse,
    OTXFeedResponse,
    OTXPulseItem,
    SeverityStatsResponse,
    TacticStatsResponse,
    ThreatFoxFeedResponse,
    ThreatFoxIOCItem,
)
from backend.config import AVAILABLE_MODELS, DEFAULT_MODEL_ID, get_settings
from backend.guardrails import GuardrailViolation, validate_input
from backend.version import __version__
from backend.db import (
    get_analysis,
    get_analysis_history,
    get_severity_counts,
    get_tactic_counts,
    save_analysis,
)
from backend.ingestion.abusech_fetcher import fetch_threatfox_recent
from backend.ingestion.cisa_kev import is_in_kev
from backend.ingestion.nvd_fetcher import fetch_cve, fetch_recent_cves
from backend.ingestion.otx_fetcher import fetch_otx_recent_pulses
from backend.metrics import agent_errors, analysis_duration, analysis_total
from backend.webhooks import fire_webhook

logger = logging.getLogger("backend.api")

router = APIRouter(prefix="/api")


# ── Helper: resolve user_id for RBAC scoping ─────────────────────────


def _scoped_user_id(user: CurrentUser) -> int | None:
    """Return user_id for DB queries: analyst sees own data, admin sees all."""
    if user.role == "admin":
        return None
    return user.id


# ---------------------------------------------------------------------------
# Version (public, no auth)
# ---------------------------------------------------------------------------


@router.get("/version")
async def get_app_version():
    """Return the current application version."""
    return {"version": __version__}


# ---------------------------------------------------------------------------
# Models (public, no auth)
# ---------------------------------------------------------------------------


@router.get("/models")
async def list_models():
    """Return available LLM models with metadata."""
    models = []
    for model_id, info in AVAILABLE_MODELS.items():
        models.append({
            "id": model_id,
            "display_name": info["display_name"],
            "description": info["description"],
            "size": info["size"],
            "default": info.get("default", False),
        })
    return {"models": models, "default": DEFAULT_MODEL_ID}


# ---------------------------------------------------------------------------
# Health (public, no auth)
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check connectivity to Ollama and Qdrant."""
    import httpx

    settings = get_settings()

    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            ollama_ok = resp.status_code == 200
    except Exception:
        logger.debug("Ollama health check failed", exc_info=True)

    qdrant_ok = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{settings.qdrant_host}:{settings.qdrant_port}")
            qdrant_ok = resp.status_code == 200
    except Exception:
        logger.debug("Qdrant health check failed", exc_info=True)

    return HealthResponse(
        status="ok" if ollama_ok else "degraded",
        ollama_connected=ollama_ok,
        qdrant_connected=qdrant_ok,
    )


# ---------------------------------------------------------------------------
# CVE Lookup
# ---------------------------------------------------------------------------


@router.get("/cve/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Fetch CVE details from NVD API."""
    data = await fetch_cve(cve_id)
    return CVEResponse(**data)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@router.post("/analyze/stream")
@limiter.limit(lambda: get_settings().rate_limit_analyze)
async def stream_analysis(
    request: Request,
    body: AnalysisRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Run the full agent pipeline with SSE streaming updates."""
    # Input guardrails
    try:
        input_warnings = validate_input(body.cve_id, body.cve_description)
    except GuardrailViolation as e:
        raise HTTPException(status_code=422, detail=e.message)

    async def event_generator():
        # Emit input warnings if any
        if input_warnings:
            yield {
                "event": "guardrail",
                "data": json.dumps({"type": "input_warning", "issues": input_warnings}),
            }

        model_id = body.model or DEFAULT_MODEL_ID
        initial_state = {
            "cve_id": body.cve_id,
            "cve_description": body.cve_description,
            "model_id": model_id,
            "extracted_info": {},
            "attack_techniques": [],
            "rag_context": "",
            "response_playbook": "",
            "sigma_rule": "",
            "guardrail_issues": [],
            "messages": [],
        }

        final_state: dict = {}
        t0 = time.perf_counter()

        try:
            loop = asyncio.get_event_loop()
            stream = await loop.run_in_executor(None, lambda: list(graph.stream(initial_state)))

            for event in stream:
                if await request.is_disconnected():
                    break

                for node_name, output in event.items():
                    final_state.update(output)
                    yield {
                        "event": "agent_update",
                        "data": json.dumps(
                            {
                                "agent": node_name,
                                "output": {k: v for k, v in output.items() if k != "messages"},
                            },
                            default=str,
                        ),
                    }

            elapsed = time.perf_counter() - t0
            analysis_duration.observe(elapsed)

            # Persist result
            try:
                await save_analysis(
                    cve_id=body.cve_id,
                    cve_description=body.cve_description,
                    extracted_info=final_state.get("extracted_info", {}),
                    attack_techniques=final_state.get("attack_techniques", []),
                    response_playbook=final_state.get("response_playbook", ""),
                    sigma_rule=final_state.get("sigma_rule", ""),
                    user_id=current_user.id if current_user.id != 0 else None,
                )
            except Exception:
                logger.warning("Failed to persist analysis for %s", body.cve_id, exc_info=True)

            # Metrics + webhook
            severity = final_state.get("extracted_info", {}).get("nvd_severity") or final_state.get(
                "extracted_info", {}
            ).get("severity_assessment", "UNKNOWN")
            analysis_total.labels(severity=severity or "UNKNOWN").inc()
            fire_webhook(
                cve_id=body.cve_id,
                severity=severity or "UNKNOWN",
                summary=final_state.get("extracted_info", {}).get("summary", ""),
                techniques=final_state.get("attack_techniques", []),
            )

            # Emit output guardrail results
            guardrail_issues = final_state.get("guardrail_issues", [])
            if guardrail_issues:
                yield {
                    "event": "guardrail",
                    "data": json.dumps({"type": "output_issues", "issues": guardrail_issues}),
                }

            yield {
                "event": "done",
                "data": json.dumps({"status": "complete"}),
            }

        except Exception as e:
            logger.exception("Stream analysis failed for %s", body.cve_id)
            agent_errors.labels(agent_name="pipeline").inc()
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }

    return EventSourceResponse(event_generator())


@router.post("/analyze", response_model=AnalysisResponse)
@limiter.limit(lambda: get_settings().rate_limit_analyze)
async def analyze(
    request: Request,
    body: AnalysisRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Run the full agent pipeline (non-streaming, returns complete result)."""
    try:
        validate_input(body.cve_id, body.cve_description)
    except GuardrailViolation as e:
        raise HTTPException(status_code=422, detail=e.message)

    model_id = body.model or DEFAULT_MODEL_ID
    initial_state = {
        "cve_id": body.cve_id,
        "cve_description": body.cve_description,
        "model_id": model_id,
        "extracted_info": {},
        "attack_techniques": [],
        "rag_context": "",
        "response_playbook": "",
        "sigma_rule": "",
        "guardrail_issues": [],
        "messages": [],
    }

    t0 = time.perf_counter()
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: graph.invoke(initial_state))
    elapsed = time.perf_counter() - t0
    analysis_duration.observe(elapsed)

    # Persist
    try:
        await save_analysis(
            cve_id=result.get("cve_id", body.cve_id),
            cve_description=body.cve_description,
            extracted_info=result.get("extracted_info", {}),
            attack_techniques=result.get("attack_techniques", []),
            response_playbook=result.get("response_playbook", ""),
            sigma_rule=result.get("sigma_rule", ""),
            user_id=current_user.id if current_user.id != 0 else None,
        )
    except Exception:
        logger.warning("Failed to persist analysis for %s", body.cve_id, exc_info=True)

    # Metrics + webhook
    severity = result.get("extracted_info", {}).get("nvd_severity") or result.get(
        "extracted_info", {}
    ).get("severity_assessment", "UNKNOWN")
    analysis_total.labels(severity=severity or "UNKNOWN").inc()
    fire_webhook(
        cve_id=result.get("cve_id", body.cve_id),
        severity=severity or "UNKNOWN",
        summary=result.get("extracted_info", {}).get("summary", ""),
        techniques=result.get("attack_techniques", []),
    )

    return AnalysisResponse(
        cve_id=result.get("cve_id", body.cve_id),
        extracted_info=result.get("extracted_info", {}),
        attack_techniques=result.get("attack_techniques", []),
        response_playbook=result.get("response_playbook", ""),
        sigma_rule=result.get("sigma_rule", ""),
    )


# ---------------------------------------------------------------------------
# Feeds
# ---------------------------------------------------------------------------


@router.get("/feed/recent", response_model=FeedResponse)
@limiter.limit(lambda: get_settings().rate_limit_feed)
async def get_recent_feed(
    request: Request,
    days: int = 7,
    limit: int = 20,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Fetch recently modified CVEs from NVD, cross-referenced with CISA KEV."""
    cves = await fetch_recent_cves(days=days, max_results=limit)

    items = [
        FeedItem(
            cve_id=cve["cve_id"],
            description=cve.get("description", ""),
            cvss_score=cve.get("cvss_score"),
            severity=cve.get("severity", "UNKNOWN"),
            published=cve.get("published"),
            cwes=cve.get("cwes", []),
            in_kev=is_in_kev(cve["cve_id"]),
        )
        for cve in cves
    ]

    return FeedResponse(items=items, count=len(items))


@router.get("/feed/otx", response_model=OTXFeedResponse)
@limiter.limit(lambda: get_settings().rate_limit_feed)
async def get_otx_feed(
    request: Request,
    days: int = 7,
    limit: int = 20,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Fetch recent OTX threat pulses."""
    pulses = await fetch_otx_recent_pulses(days=days, limit=limit)
    items = [OTXPulseItem(**p) for p in pulses]
    return OTXFeedResponse(items=items, count=len(items))


@router.get("/feed/threatfox", response_model=ThreatFoxFeedResponse)
@limiter.limit(lambda: get_settings().rate_limit_feed)
async def get_threatfox_feed(
    request: Request,
    days: int = 7,
    limit: int = 50,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Fetch recent ThreatFox IOCs."""
    iocs = await fetch_threatfox_recent(days=days, limit=limit)
    items = [ThreatFoxIOCItem(**i) for i in iocs]
    return ThreatFoxFeedResponse(items=items, count=len(items))


# ---------------------------------------------------------------------------
# Dashboard Stats
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: CurrentUser = Depends(get_current_user),
):
    """Return Qdrant collection stats and service connectivity for the dashboard."""
    import httpx

    settings = get_settings()

    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            ollama_ok = resp.status_code == 200
    except Exception:
        logger.debug("Ollama health check failed", exc_info=True)

    qdrant_ok = False
    counts: dict[str, int] = {}
    total = 0
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{settings.qdrant_host}:{settings.qdrant_port}")
            qdrant_ok = resp.status_code == 200

            if qdrant_ok:
                resp = await client.get(
                    f"http://{settings.qdrant_host}:{settings.qdrant_port}"
                    f"/collections/{settings.qdrant_collection}"
                )
                if resp.status_code == 200:
                    info = resp.json().get("result", {})
                    total = info.get("points_count", 0)

                for chunk_type in [
                    "technique",
                    "mitigation",
                    "software",
                    "group",
                    "relationship",
                ]:
                    resp = await client.post(
                        f"http://{settings.qdrant_host}:{settings.qdrant_port}"
                        f"/collections/{settings.qdrant_collection}/points/count",
                        json={
                            "filter": {
                                "must": [
                                    {
                                        "key": "chunk_type",
                                        "match": {"value": chunk_type},
                                    }
                                ]
                            },
                            "exact": True,
                        },
                    )
                    if resp.status_code == 200:
                        counts[chunk_type] = resp.json().get("result", {}).get("count", 0)
    except Exception:
        logger.debug("Qdrant stats check failed", exc_info=True)

    return DashboardStats(
        total_chunks=total,
        technique_chunks=counts.get("technique", 0),
        mitigation_chunks=counts.get("mitigation", 0),
        software_chunks=counts.get("software", 0),
        group_chunks=counts.get("group", 0),
        relationship_chunks=counts.get("relationship", 0),
        ollama_connected=ollama_ok,
        qdrant_connected=qdrant_ok,
    )


# ---------------------------------------------------------------------------
# Analysis History
# ---------------------------------------------------------------------------


@router.get("/history", response_model=AnalysisHistoryResponse)
async def get_history(
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Fetch paginated analysis history. Analysts see only their own."""
    items = await get_analysis_history(
        limit=limit, offset=offset, user_id=_scoped_user_id(current_user)
    )
    return AnalysisHistoryResponse(
        items=[AnalysisHistoryItem(**i) for i in items],
        count=len(items),
    )


@router.get("/history/stats/severity", response_model=SeverityStatsResponse)
async def get_severity_stats(
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get analysis counts grouped by severity."""
    counts = await get_severity_counts(user_id=_scoped_user_id(current_user))
    return SeverityStatsResponse(counts=counts)


@router.get("/history/stats/tactics", response_model=TacticStatsResponse)
async def get_tactic_stats(
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get analysis counts grouped by ATT&CK tactic."""
    counts = await get_tactic_counts(user_id=_scoped_user_id(current_user))
    return TacticStatsResponse(counts=counts)


@router.get("/history/{analysis_id}")
async def get_history_item(
    analysis_id: int,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Fetch a single analysis by ID. Analysts can only access their own."""
    item = await get_analysis(analysis_id, user_id=_scoped_user_id(current_user))
    if not item:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return item

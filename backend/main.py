"""Sentinel SOC v4 — FastAPI application shell."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field, field_validator

import actions
import alerts as alert_svc
import blocker
import cases as case_svc
import config
import database as db
import honeypots
import live_attacks
import playbooks
from pipeline import on_event, publish, subscribe, unsubscribe

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sentinel")

@asynccontextmanager
async def lifespan(_: FastAPI):
    tasks = await _startup()
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(
    title="Sentinel SOC",
    version="4.0.0",
    docs_url="/api/docs" if config.PUBLIC_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.PUBLIC_DOCS else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def auth(key: str = Security(_key_header)) -> str:
    if key != config.API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
    return key


def analyst_id(x_analyst: str | None = Header(default=None, alias="X-Analyst")) -> str:
    return x_analyst or "alice"


# ── Request models ────────────────────────────────────────────────────────────

class AssignBody(BaseModel):
    assignee: str


class ResolveBody(BaseModel):
    reason: str = ""


class CaseCreate(BaseModel):
    title: str
    severity: str = "high"
    assignee: str = "alice"
    alert_ids: list[int] = Field(default_factory=list)
    campaign_id: int | None = None
    sla_minutes: int = 60


class CaseUpdate(BaseModel):
    title: str | None = None
    severity: str | None = None
    status: str | None = None
    assignee: str | None = None
    close_reason: str | None = None


class CaseNote(BaseModel):
    text: str


class BlockBody(BaseModel):
    ip: str
    reason: str = "manual containment"
    hours: int | None = Field(default=24, ge=1, le=8760)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("must be a valid IPv4 or IPv6 address")


class PlaybookRun(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)


class SimulatorBody(BaseModel):
    enabled: bool


# ── Legacy / core ─────────────────────────────────────────────────────────────

@app.get("/api/events", dependencies=[Security(auth)])
def api_events(
    limit: int = Query(100, ge=1, le=1000),
    severity: str | None = Query(None),
    ip: str | None = Query(None),
    source: str | None = Query(None, description="'sensor' (real) or 'simulator' (demo)"),
):
    return db.get_events(limit=limit, severity=severity, ip=ip, source=source)


@app.get("/api/stats", dependencies=[Security(auth)])
def api_stats():
    return db.get_stats()


@app.get("/api/export", dependencies=[Security(auth)])
def api_export():
    return db.get_events(limit=50_000)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": "4.0.0",
        # `available` = this build ships the generator at all.
        # `running`   = it is currently emitting (analyst can pause it live).
        "simulator_available": config.LIVE_ATTACKS,
        "simulator_running": config.LIVE_ATTACKS and live_attacks.is_running(),
        "firewall_enforcement": blocker.enforcement_status(),
    }


@app.post("/api/simulator", dependencies=[Security(auth)])
def api_simulator(
    body: SimulatorBody,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    """Pause or resume the ambient attack generator without a restart."""
    if not config.LIVE_ATTACKS:
        raise HTTPException(409, "simulator is disabled for this deployment")
    actor = x_analyst or "alice"
    running = live_attacks.set_running(body.enabled)
    db.add_audit(
        actor,
        "simulator_resume" if running else "simulator_pause",
        "live_attacks",
        "ambient demo traffic " + ("resumed" if running else "paused"),
    )
    state = {"simulator_available": True, "simulator_running": running}
    publish("simulator", state)
    return state


@app.get("/api/analysts", dependencies=[Security(auth)])
def api_analysts():
    return db.list_analysts()


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts", dependencies=[Security(auth)])
def api_list_alerts(
    limit: int = Query(100, ge=1, le=500),
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
    ip: str | None = None,
):
    return db.list_alerts(limit=limit, status=status, severity=severity, assignee=assignee, ip=ip)


@app.get("/api/alerts/{alert_id}", dependencies=[Security(auth)])
def api_get_alert(alert_id: int):
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@app.post("/api/alerts/{alert_id}/ack", dependencies=[Security(auth)])
def api_ack(alert_id: int, x_analyst: str | None = Header(default=None, alias="X-Analyst")):
    actor = x_analyst or "alice"
    alert = alert_svc.acknowledge(alert_id, actor)
    if not alert:
        raise HTTPException(404, "Alert not found")
    publish("alert", alert)
    return alert


@app.post("/api/alerts/{alert_id}/assign", dependencies=[Security(auth)])
def api_assign(
    alert_id: int,
    body: AssignBody,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    alert = alert_svc.assign(alert_id, body.assignee, actor)
    if not alert:
        raise HTTPException(404, "Alert not found")
    publish("alert", alert)
    return alert


@app.post("/api/alerts/{alert_id}/investigate", dependencies=[Security(auth)])
def api_investigate_alert(
    alert_id: int,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    alert = alert_svc.set_investigating(alert_id, actor)
    if not alert:
        raise HTTPException(404, "Alert not found")
    publish("alert", alert)
    return alert


@app.post("/api/alerts/{alert_id}/escalate", dependencies=[Security(auth)])
def api_escalate(
    alert_id: int,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    alert = alert_svc.escalate(alert_id, actor)
    if not alert:
        raise HTTPException(404, "Alert not found")
    publish("alert", alert)
    return alert


@app.post("/api/alerts/{alert_id}/resolve", dependencies=[Security(auth)])
def api_resolve(
    alert_id: int,
    body: ResolveBody | None = None,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    reason = body.reason if body else ""
    alert = alert_svc.resolve(alert_id, actor, reason)
    if not alert:
        raise HTTPException(404, "Alert not found")
    publish("alert", alert)
    return alert


@app.post("/api/alerts/{alert_id}/false-positive", dependencies=[Security(auth)])
def api_fp(
    alert_id: int,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    alert = alert_svc.false_positive(alert_id, actor)
    if not alert:
        raise HTTPException(404, "Alert not found")
    publish("alert", alert)
    return alert


# ── Cases ─────────────────────────────────────────────────────────────────────

@app.get("/api/cases", dependencies=[Security(auth)])
def api_list_cases(limit: int = Query(50, ge=1, le=200), status: str | None = None):
    return db.list_cases(limit=limit, status=status)


@app.get("/api/cases/{case_id}", dependencies=[Security(auth)])
def api_get_case(case_id: int):
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@app.post("/api/cases", dependencies=[Security(auth)])
def api_create_case(
    body: CaseCreate,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    case = case_svc.open_case(
        title=body.title,
        severity=body.severity,
        assignee=body.assignee,
        alert_ids=body.alert_ids,
        campaign_id=body.campaign_id,
        sla_minutes=body.sla_minutes,
        actor=actor,
    )
    publish("case", case)
    return case


@app.patch("/api/cases/{case_id}", dependencies=[Security(auth)])
def api_update_case(
    case_id: int,
    body: CaseUpdate,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if fields.get("status") == "closed":
        case = case_svc.close_case(case_id, actor, fields.get("close_reason", ""))
    else:
        case = db.update_case(case_id, **fields)
        if case:
            db.add_audit(actor, "update_case", f"case:{case_id}", json.dumps(fields))
    if not case:
        raise HTTPException(404, "Case not found")
    publish("case", case)
    return case


@app.post("/api/cases/{case_id}/notes", dependencies=[Security(auth)])
def api_case_note(
    case_id: int,
    body: CaseNote,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    case = db.add_case_note(case_id, actor, body.text)
    if not case:
        raise HTTPException(404, "Case not found")
    db.add_audit(actor, "case_note", f"case:{case_id}", body.text[:200])
    publish("case", case)
    return case


# ── Campaigns / investigate ───────────────────────────────────────────────────

@app.get("/api/campaigns", dependencies=[Security(auth)])
def api_campaigns(limit: int = Query(50, ge=1, le=200), status: str | None = None):
    return db.list_campaigns(limit=limit, status=status)


@app.get("/api/campaigns/{campaign_id}", dependencies=[Security(auth)])
def api_campaign(campaign_id: int):
    camp = db.get_campaign(campaign_id)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    alerts = [a for a in db.list_alerts(limit=200) if a.get("campaign_id") == campaign_id]
    return {**camp, "alerts": alerts}


@app.get("/api/investigate/{ip}", dependencies=[Security(auth)])
def api_investigate(ip: str):
    return db.investigate_ip(ip)


# ── Blocklist / playbooks / audit / metrics ───────────────────────────────────

@app.get("/api/blocklist", dependencies=[Security(auth)])
def api_blocklist(all: bool = Query(False)):
    return db.list_blocks(active_only=not all)


@app.post("/api/blocklist", dependencies=[Security(auth)])
def api_block(
    body: BlockBody,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    result = actions.contain_ip(
        body.ip,
        reason=body.reason,
        source="manual",
        actor=actor,
        hours=body.hours,
    )
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "block failed"))
    publish("action", {"action": "contain", **result})
    return result


@app.delete("/api/blocklist/{ip}", dependencies=[Security(auth)])
def api_unblock(
    ip: str,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    if not blocker.is_valid_ip(ip):
        raise HTTPException(422, "invalid IP address")
    result = actions.release_ip(ip, actor=actor)
    publish("action", {"action": "release", **result})
    return result


@app.get("/api/playbooks", dependencies=[Security(auth)])
def api_playbooks():
    return playbooks.list_playbooks()


@app.post("/api/playbooks/{playbook_id}/run", dependencies=[Security(auth)])
def api_run_playbook(
    playbook_id: str,
    body: PlaybookRun | None = None,
    x_analyst: str | None = Header(default=None, alias="X-Analyst"),
):
    actor = x_analyst or "alice"
    params = body.params if body else {}
    result = playbooks.run_playbook(playbook_id, params, actor=actor)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "playbook failed"))
    publish("action", {"action": "playbook", "playbook_id": playbook_id, "result": result})
    if "alert" in result:
        publish("alert", result["alert"])
    if "case" in result:
        publish("case", result["case"])
    return result


@app.get("/api/audit", dependencies=[Security(auth)])
def api_audit(limit: int = Query(100, ge=1, le=500)):
    return db.list_audit(limit=limit)


@app.get("/api/metrics", dependencies=[Security(auth)])
def api_metrics():
    return db.get_metrics()


@app.get("/api/geo/points", dependencies=[Security(auth)])
def api_geo_points(limit: int = Query(80, ge=1, le=300)):
    """Active threat origins with coordinates for the live map."""
    return db.get_geo_points(limit=limit)


# ── SSE ───────────────────────────────────────────────────────────────────────

@app.get("/api/stream")
async def api_stream(key: str = Query(None)):
    if key != config.API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

    async def generator():
        q = subscribe()
        try:
            yield f"data: {json.dumps({'type': 'hello', 'data': {'version': '4.0.0'}, 'seq': 0})}\n\n"
            while True:
                try:
                    envelope = await asyncio.wait_for(q.get(), timeout=12.0)
                    yield f"data: {json.dumps(envelope)}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'ping', 'data': {}, 'seq': 0})}\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            unsubscribe(q)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Background tasks ──────────────────────────────────────────────────────────

async def _expiry_loop() -> None:
    while True:
        try:
            released = actions.sweep_expired(actor="system")
            for r in released:
                publish("action", {"action": "expiry_release", **r})
        except Exception as exc:
            log.debug("expiry sweep: %s", exc)
        await asyncio.sleep(60)


def _seed_if_empty() -> None:
    """
    Populate demo history on a cold, empty database.

    Only relevant on hosts without a persistent disk, where every restart
    starts from nothing. Guarded on the events table being empty so it can
    never wipe real data.
    """
    if db.count_events() > 0:
        return
    log.info("Empty database — seeding 7 days of demo history")
    try:
        from seed_data import seed

        seed()
        log.info("Seed complete: %s events", db.count_events())
    except Exception as exc:
        log.error("Seeding failed, continuing with an empty database: %s", exc)


async def _startup() -> list[asyncio.Task]:
    db.init_db()
    if config.SEED_ON_EMPTY:
        _seed_if_empty()
    try:
        from enrichment import start_intel_refresh

        start_intel_refresh()
    except Exception as exc:
        log.warning("Intel refresh not started: %s", exc)
    active = [b["ip"] for b in db.list_blocks(active_only=True)]
    blocker.sync_from_db(active)

    fw = blocker.enforcement_status()
    if not fw["available"]:
        log.warning("Containment DEGRADED — %s", fw["note"])

    sensors = [
        ("ssh", config.SSH_PORT, honeypots.ssh),
        ("http", config.HTTP_PORT, honeypots.http),
        ("ftp", config.FTP_PORT, honeypots.ftp),
        ("telnet", config.TELNET_PORT, honeypots.telnet),
    ]
    tasks = [asyncio.create_task(_expiry_loop())]
    used = {config.API_PORT}
    for name, port, runner in sensors:
        if port in used:
            log.warning(
                "Skipping %s honeypot — port %s is already the API port. "
                "Set HTTP_PORT (or the matching *_PORT) to a free number.",
                name,
                port,
            )
            continue
        used.add(port)
        tasks.append(asyncio.create_task(runner(port, on_event)))
    if config.LIVE_ATTACKS:
        tasks.append(asyncio.create_task(
            live_attacks.run_live_attacks(on_event, interval=config.LIVE_ATTACK_INTERVAL)
        ))
        log.info(
            "Sentinel SOC v4.0 online — honeypots + SOAR. Simulator ON: "
            "ambient events are tagged source='simulator'."
        )
    else:
        log.info("Sentinel SOC v4.0 online — honeypots + SOAR. Simulator OFF: sensor traffic only.")
    return tasks

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest, urlopen

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

if __package__:
    from .cyber_fusion import CyberFusionEngine
    from .enterprise import AuthManager, CaseStore, UserContext
    from .risk_engine import RiskEngine
    from .scamcheck import ScamCheckCacheStore, ScamCheckService
    from .threat_intel import ThreatIntelEngine
else:
    from cyber_fusion import CyberFusionEngine
    from enterprise import AuthManager, CaseStore, UserContext
    from risk_engine import RiskEngine
    from scamcheck import ScamCheckCacheStore, ScamCheckService
    from threat_intel import ThreatIntelEngine


# ─────────────────────────────────────────────────────
# Request/response models
# ─────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)


class BatchAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=100)


class WebsiteTraceRequest(BaseModel):
    url: str = Field(..., min_length=3)
    max_pages: int = Field(default=120, ge=1, le=500)
    max_depth: int = Field(default=4, ge=0, le=8)
    include_external: bool = Field(default=False)
    exhaustive: bool = Field(default=True)


class FusionScanRequest(BaseModel):
    text: Optional[str] = None
    website_url: Optional[str] = None
    max_pages: int = Field(default=80, ge=1, le=500)
    max_depth: int = Field(default=3, ge=0, le=8)
    include_external: bool = False
    exhaustive: bool = True


class ThreatIntelRequest(BaseModel):
    text: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    live_feeds: Optional[bool] = None


class ScamCheckRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=8000)
    detectedType: str = Field(..., min_length=1, max_length=24)


class WebsiteIntelRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2000)


class FileAnalysisResult(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    risk_score: int
    risk_level: str
    suspicious_signals: List[str]
    ioc_intelligence: Dict[str, Any] = Field(default_factory=dict)


class FileAnalyzeRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=300)
    content_base64: str = Field(..., min_length=1)


class CaseCreateRequest(BaseModel):
    source_type: str = Field(default="manual")
    source_value: Optional[str] = None
    title: str = Field(..., min_length=3, max_length=240)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    status: str = Field(default="new", pattern="^(new|triaged|escalated|closed)$")
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    findings: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    scan_result: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None


class CaseFromAnalysisRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=240)
    text: str = Field(..., min_length=1)
    tags: List[str] = Field(default_factory=list)
    assigned_to: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=240)
    severity: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    status: Optional[str] = Field(default=None, pattern="^(new|triaged|escalated|closed)$")
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None
    notes: Optional[str] = None


class CommentCreateRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1200)


class FeedConfigRequest(BaseModel):
    alienvault_otx: Optional[str] = None
    abuseipdb: Optional[str] = None
    virustotal: Optional[str] = None


# ─────────────────────────────────────────────────────
# Application bootstrap
# ─────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DEFAULT_DATA_DIR = "/tmp/riskintel" if os.getenv("VERCEL") else str(BASE_DIR / "data")
DATA_DIR = Path(os.getenv("RISKINTEL_DATA_DIR", DEFAULT_DATA_DIR))
logger = logging.getLogger("riskintel")


def _load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and os.getenv(key) is None:
                os.environ[key] = value
    except OSError:
        pass


def _sync_feed_env_aliases() -> None:
    alias_pairs = {
        "OTX_API_KEY": "RISKINTEL_OTX_API_KEY",
        "ABUSEIPDB_API_KEY": "RISKINTEL_ABUSEIPDB_API_KEY",
        "VIRUSTOTAL_API_KEY": "RISKINTEL_VT_API_KEY",
        "SHODAN_API_KEY": "RISKINTEL_SHODAN_API_KEY",
        "URLSCAN_API_KEY": "RISKINTEL_URLSCAN_API_KEY",
    }
    for alias, canonical in alias_pairs.items():
        alias_value = os.getenv(alias, "").strip()
        canonical_value = os.getenv(canonical, "").strip()
        if alias_value and not canonical_value:
            os.environ[canonical] = alias_value
        elif canonical_value and not alias_value:
            os.environ[alias] = canonical_value


_load_dotenv(BASE_DIR.parent / ".env")
_sync_feed_env_aliases()

engine = RiskEngine()
fusion_engine = CyberFusionEngine(engine)
threat_intel_engine = ThreatIntelEngine()
auth_manager = AuthManager()
case_store = CaseStore(DATA_DIR / "riskintel.db")
scamcheck_cache = ScamCheckCacheStore(DATA_DIR / "riskintel.db")
scamcheck_service = ScamCheckService(threat_intel_engine, engine, scamcheck_cache)

app = FastAPI(
    title="Risk Intelligence System",
    version="3.0.0",
    description="Async hybrid fraud/threat detection - rules + NLP + live IOC feeds",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1024)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

AUTH_ENFORCED = os.getenv("RISKINTEL_ENFORCE_AUTH", "true").lower() == "true"
DEFAULT_API_KEY = os.getenv("RISKINTEL_DEFAULT_API_KEY", "").strip()
_feed_status_cache: Dict[str, Any] = {"feeds": [], "summary": {"configured": 0, "reachable": 0, "auth_valid": 0, "total": 0}}


def _feed_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _reload_feed_keys() -> None:
    threat_intel_engine.otx_key = _feed_env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")
    threat_intel_engine.abuseipdb_key = _feed_env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")
    threat_intel_engine.vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    threat_intel_engine.shodan_key = _feed_env("SHODAN_API_KEY", "RISKINTEL_SHODAN_API_KEY")
    threat_intel_engine.urlscan_key = _feed_env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")


def _live_feeds_default() -> bool:
    return (
        os.getenv("RISKINTEL_USE_LIVE_FEEDS", "true").lower() == "true"
        and threat_intel_engine.live_feeds_available
    )


def _build_feed_configs() -> Dict[str, Dict[str, Any]]:
    return {
        "alienvault_otx": {"name": "AlienVault OTX", "api_key": threat_intel_engine.otx_key, "enabled": bool(threat_intel_engine.otx_key), "health_check_url": "https://otx.alienvault.com/api/v1/user/me"},
        "abuseipdb": {"name": "AbuseIPDB", "api_key": threat_intel_engine.abuseipdb_key, "enabled": bool(threat_intel_engine.abuseipdb_key), "health_check_url": "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30"},
        "virustotal": {"name": "VirusTotal", "api_key": threat_intel_engine.vt_key, "enabled": bool(threat_intel_engine.vt_key), "health_check_url": "https://www.virustotal.com/api/v3/users/current"},
        "shodan": {"name": "Shodan", "api_key": threat_intel_engine.shodan_key, "enabled": bool(threat_intel_engine.shodan_key), "health_check_url": f"https://api.shodan.io/api-info?key={threat_intel_engine.shodan_key}" if threat_intel_engine.shodan_key else ""},
        "urlscan": {"name": "URLScan.io", "api_key": threat_intel_engine.urlscan_key, "enabled": bool(threat_intel_engine.urlscan_key), "health_check_url": "https://urlscan.io/user/"},
    }


def _build_auth_headers(feed_name: str, api_key: str) -> Dict[str, str]:
    if feed_name == "alienvault_otx":
        return {"X-OTX-API-KEY": api_key}
    if feed_name == "abuseipdb":
        return {"Key": api_key, "Accept": "application/json"}
    if feed_name == "virustotal":
        return {"x-apikey": api_key}
    if feed_name == "urlscan":
        return {"API-Key": api_key}
    return {}


async def _probe_feed(feed_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    if not config.get("api_key") or not config.get("enabled") or not config.get("health_check_url"):
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": False, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": None, "last_checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    headers = _build_auth_headers(feed_name, config["api_key"])
    headers["User-Agent"] = "RiskIntel/3.0"
    logger.info("Feed probe %s url=%s headers=%s", feed_name, config["health_check_url"], {k: (_mask_secret(v) if "key" in k.lower() else v) for k, v in headers.items()})
    try:
        started = time.monotonic()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(config["health_check_url"], headers=headers)
        latency_ms = int((time.monotonic() - started) * 1000)
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": response.status_code < 500, "auth_valid": response.status_code not in (401, 403), "latency_ms": latency_ms, "http_status": response.status_code, "error": None if response.status_code < 500 else f"HTTP {response.status_code}", "last_checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": str(exc), "last_checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _patched_intent_profile(self: RiskEngine, text: str) -> Dict[str, object]:
    templates = {
        "romance_fraud": ["i love you", "send money", "emergency abroad", "military deployment", "offshore account"],
        "lottery_fraud": ["you have won", "claim your prize", "lottery winner", "transfer fee required"],
        "phishing_credential_theft": ["verify your account", "click here to login", "your password has expired", "confirm your identity"],
        "advance_fee_fraud": ["million dollars", "inheritance", "need your help to transfer", "percentage commission"],
        "tech_support_scam": ["your computer is infected", "call microsoft", "remote access", "your ip was hacked"],
    }
    norm = self._normalize(text)
    if len(norm.strip()) < 10:
        return {"top_intents": [], "max_similarity": 0.0}
    query_vector = self._vectorize(norm)
    scores = []
    for intent, items in templates.items():
        sims = [self._cosine(query_vector, self._vectorize(self._normalize(item))) for item in items]
        best = max(sims) if sims else 0.0
        scores.append({"intent": intent, "similarity": round(best * 100, 1)})
    top = sorted(scores, key=lambda item: item["similarity"], reverse=True)[:4]
    return {"top_intents": top, "max_similarity": top[0]["similarity"] if top else 0.0}


def _patched_whois_domain_age_profile(self: RiskEngine, hostname: str) -> Dict[str, object]:
    host = (hostname or "").strip().lower()
    if not host:
        return {"score": 0.0, "flags": [], "age_days": None, "status": "unavailable"}

    cached = self._global_whois_cache.get(host)
    if cached is not None:
        return cached

    root = self._effective_domain(host)
    score = 0.0
    flags: List[str] = []
    age_days: Optional[int] = None
    creation_date: Optional[str] = None
    status = "unavailable"

    risk_engine_module = sys.modules.get("risk_engine") or sys.modules.get("app.risk_engine")
    python_whois = getattr(risk_engine_module, "python_whois", None) if risk_engine_module else None
    if python_whois is not None:
        try:
            record = python_whois.whois(root)
            created = getattr(record, "creation_date", None)
            if isinstance(created, list):
                created = created[0] if created else None
            if created:
                if getattr(created, "tzinfo", None) is not None:
                    created = created.replace(tzinfo=None)
                age_days = max(0, (datetime.utcnow() - created).days)
                creation_date = created.isoformat()
                status = "ok"
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", root, exc)

    if age_days is None:
        try:
            req = UrlRequest(
                f"https://rdap.org/domain/{root}",
                headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"},
            )
            with urlopen(req, timeout=8.0) as response:
                payload = response.read(240000).decode("utf-8", errors="ignore")
            match = self._re_whois_date.search(payload)
            if match:
                year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                creation_date = created.isoformat()
                status = "ok"
        except Exception as exc:
            logger.warning("RDAP lookup failed for %s: %s", root, exc)

    if age_days is not None:
        if age_days < 30:
            score += 0.23; flags.append("Very new domain (<30 days)")
        elif age_days < 90:
            score += 0.16; flags.append("Recently registered (<90 days)")
        elif age_days < 180:
            score += 0.10; flags.append("Young domain (<180 days)")

    out = {
        "score": round(min(0.3, score), 3),
        "flags": flags,
        "age_days": age_days,
        "creation_date": creation_date,
        "status": status,
    }
    self._global_whois_cache.set(host, out)
    return out


def _patched_domain_reputation_profile(self: RiskEngine, hostname: str) -> Dict[str, object]:
    host = (hostname or "").strip().lower()
    base = {"score": 0.0, "flags": [], "category": "unknown", "reputation": "unknown", "sources": []}
    if not host:
        return base

    original = getattr(self, "_original_domain_reputation_profile", None)
    if callable(original):
        base.update(original(host))
    else:
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

    sources: List[Dict[str, Any]] = []
    total_malicious = 0
    vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    if vt_key:
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                response = client.get(
                    f"https://www.virustotal.com/api/v3/domains/{host}",
                    headers={"x-apikey": vt_key, "User-Agent": "RiskIntel/3.0"},
                )
            if response.status_code == 200:
                vt_data = response.json()
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                total_malicious += malicious + suspicious
                sources.append({
                    "source": "virustotal",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "http_status": response.status_code,
                })
            else:
                sources.append({"source": "virustotal", "malicious": 0, "http_status": response.status_code})
        except Exception as exc:
            logger.warning("VirusTotal domain reputation lookup failed for %s: %s", host, exc)

    if total_malicious <= 0:
        reputation = "clean" if sources else "unknown"
    elif total_malicious < 3:
        reputation = "suspicious"
    else:
        reputation = "malicious"

    base["sources"] = sources
    base["reputation"] = reputation
    base["total_malicious_hits"] = total_malicious
    if total_malicious > 0:
        base["score"] = round(min(1.0, float(base.get("score", 0.0)) + min(0.45, total_malicious * 0.08)), 3)
        flags = list(base.get("flags", []))
        flags.append(f"VirusTotal reports {total_malicious} malicious/suspicious detections")
        base["flags"] = flags[:8]
        base["category"] = "poor" if total_malicious >= 3 else "questionable"

    self._global_domain_cache.set(host, base)
    return base


RiskEngine._original_domain_reputation_profile = RiskEngine._domain_reputation_profile
RiskEngine._whois_domain_age_profile = _patched_whois_domain_age_profile
RiskEngine._domain_reputation_profile = _patched_domain_reputation_profile
RiskEngine._intent_profile = _patched_intent_profile
_reload_feed_keys()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception for %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "path": request.url.path},
    )


def _website_verdict_from_score(score: int) -> str:
    if score >= 70:
        return "DANGER"
    if score >= 30:
        return "CAUTION"
    return "SAFE"


def _website_summary(verdict: str, domain: str, feeds: Dict[str, Any]) -> str:
    vt = int((((feeds.get("virustotal") or {}).get("malicious")) or 0))
    abuse = int((((feeds.get("abuseipdb") or {}).get("abuseConfidence")) or 0))
    otx = int((((feeds.get("otx") or {}).get("pulseCount")) or 0))
    if verdict == "DANGER":
        if vt > 5:
            return f"Do not visit {domain}. VirusTotal flagged it across {vt} engines."
        if abuse > 50:
            return f"Proceeding is risky. Abuse intelligence is elevated for infrastructure linked to {domain}."
        return f"{domain} is tied to multiple threat-intelligence hits and should be avoided."
    if verdict == "CAUTION":
        if vt or abuse or otx:
            return f"Proceed with caution. {domain} has some suspicious reputation signals."
        return f"{domain} looks mostly clean, but there are a few signals worth double-checking."
    return f"No strong malicious signals were found for {domain}. Safe to visit with normal caution."


def _build_website_scan_result(input_url: str) -> Dict[str, Any]:
    normalized = input_url.strip()
    parsed = urlsplit(normalized if "://" in normalized else f"https://{normalized}")
    domain = (parsed.hostname or "").lower()
    if not domain or "." not in domain:
        raise ValueError(f"Invalid URL: {input_url}")
    ip = ""
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = ""

    otx_raw = threat_intel_engine._lookup_otx("domain", domain) if domain else {"source": "otx", "pulse_count": 0}
    vt_raw = threat_intel_engine._lookup_virustotal("url", normalized)
    abuse_raw = threat_intel_engine._lookup_abuseipdb("ip", ip) if ip else {"source": "abuseipdb", "abuse_confidence": 0}

    vt_malicious = int(vt_raw.get("malicious_votes", 0) or 0)
    vt_suspicious = int(vt_raw.get("suspicious_votes", 0) or 0)
    abuse_confidence = int(abuse_raw.get("abuse_confidence", 0) or 0)
    otx_pulses = int(otx_raw.get("pulse_count", 0) or 0)

    risk_score = 0
    risk_score += 40 if vt_malicious > 5 else 20 if vt_malicious >= 1 else 0
    risk_score += 30 if abuse_confidence > 50 else 15 if abuse_confidence >= 10 else 0
    risk_score += 20 if otx_pulses > 2 else 10 if otx_pulses >= 1 else 0
    risk_score = min(100, risk_score)
    verdict = _website_verdict_from_score(risk_score)

    return {
        "type": "url",
        "input": normalized,
        "domain": domain,
        "ip": ip,
        "riskScore": risk_score,
        "verdict": verdict,
        "summary": _website_summary(
            verdict,
            domain or normalized,
            {
                "otx": {"pulseCount": otx_pulses},
                "abuseipdb": {"abuseConfidence": abuse_confidence},
                "virustotal": {"malicious": vt_malicious},
            },
        ),
        "feeds": {
            "otx": {
                "pulseCount": otx_pulses,
                "threatScore": min(100, otx_pulses * 20),
                "raw": otx_raw,
            },
            "abuseipdb": {
                "abuseConfidence": abuse_confidence,
                "totalReports": int(abuse_raw.get("total_reports", 0) or 0),
                "country": abuse_raw.get("country"),
                "isp": abuse_raw.get("isp"),
                "raw": abuse_raw,
            },
            "virustotal": {
                "malicious": vt_malicious,
                "suspicious": vt_suspicious,
                "total": vt_malicious + vt_suspicious,
                "raw": vt_raw,
            },
        },
        "scannedAt": datetime.utcnow().isoformat(),
    }


async def refresh_feed_status_cache() -> Dict[str, Any]:
    global _feed_status_cache
    configs = _build_feed_configs()
    results = await asyncio.gather(*[_probe_feed(name, config) for name, config in configs.items()])
    _feed_status_cache = {
        "timestamp": datetime.utcnow().isoformat(),
        "feeds": results,
        "summary": {
            "configured": sum(1 for item in results if item.get("configured")),
            "reachable": sum(1 for item in results if item.get("reachable")),
            "auth_valid": sum(1 for item in results if item.get("auth_valid")),
            "total": len(results),
        },
    }
    return _feed_status_cache

# ─────────────────────────────────────────────────────
# In-memory response cache (TTL 60s)
# ─────────────────────────────────────────────────────
_response_cache: Dict[str, tuple] = {}
_RESPONSE_CACHE_TTL = 60.0


def _cache_key(*parts: str) -> str:
    return hashlib.md5(":".join(parts).encode()).hexdigest()


def _get_cached(key: str) -> Optional[Any]:
    entry = _response_cache.get(key)
    if entry and time.monotonic() - entry[1] < _RESPONSE_CACHE_TTL:
        return entry[0]
    return None


def _set_cached(key: str, value: Any) -> None:
    if len(_response_cache) > 2000:
        oldest = min(_response_cache.items(), key=lambda x: x[1][1])
        _response_cache.pop(oldest[0], None)
    _response_cache[key] = (value, time.monotonic())


# ─────────────────────────────────────────────────────
# Request timing middleware
# ─────────────────────────────────────────────────────
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Process-Time-Ms"] = str(elapsed_ms)
    return response


# ─────────────────────────────────────────────────────
# Request counter middleware
# ─────────────────────────────────────────────────────
_request_counters: Dict[str, int] = {}


@app.middleware("http")
async def count_requests(request: Request, call_next):
    path = request.url.path
    _request_counters[path] = _request_counters.get(path, 0) + 1
    return await call_next(request)


# ─────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────
def get_current_user(x_api_key: Optional[str] = Header(default=None)) -> UserContext:
    provided_key = (x_api_key or "").strip()
    user = auth_manager.identify(provided_key or DEFAULT_API_KEY)
    if not user.authenticated and DEFAULT_API_KEY and provided_key and provided_key != DEFAULT_API_KEY:
        user = auth_manager.identify(DEFAULT_API_KEY)
    if AUTH_ENFORCED and auth_manager.key_count == 0:
        raise HTTPException(
            status_code=503,
            detail="Authentication is enabled but RISKINTEL_API_KEYS is not configured",
        )
    if AUTH_ENFORCED and not user.authenticated:
        raise HTTPException(status_code=401, detail="Valid X-API-Key is required")
    return user


def require_roles(*roles: str):
    allowed = set(roles)

    def _dep(user: UserContext = Depends(get_current_user)) -> UserContext:
        if not user.authenticated:
            raise HTTPException(status_code=401, detail="Valid X-API-Key is required")
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail=f"Role '{user.role}' not allowed")
        return user

    return _dep


# ─────────────────────────────────────────────────────
# Static routes
# ─────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    with (STATIC_DIR / "index.html").open("r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/scamcheck", response_class=HTMLResponse)
async def scamcheck_page() -> HTMLResponse:
    with (STATIC_DIR / "scamcheck.html").open("r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/v1/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "risk-intelligence-system",
        "version": "3.0.0",
        "auth_enforced": AUTH_ENFORCED,
        "configured_api_keys": auth_manager.key_count,
        "default_api_key_configured": bool(DEFAULT_API_KEY),
        "live_feeds_available": threat_intel_engine.live_feeds_available,
        "live_feeds_default": _live_feeds_default(),
        "data_dir": str(DATA_DIR),
        "live_feed_status": threat_intel_engine.live_feed_status,
        "engine_cache_sizes": {
            "link_cache": len(engine._global_link_cache),
            "domain_cache": len(engine._global_domain_cache),
            "whois_cache": len(engine._global_whois_cache),
        },
    }


@app.on_event("startup")
async def startup_diagnostics() -> None:
    logger.info("=== CRIE v3.0 STARTUP DIAGNOSTICS ===")
    for env_names in (
        ("OTX_API_KEY", "RISKINTEL_OTX_API_KEY"),
        ("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY"),
        ("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY"),
    ):
        env_key = env_names[0]
        value = _feed_env(*env_names)
        if value:
            logger.info("  %s: configured (%s chars)", env_key, len(value))
        else:
            logger.warning("  %s: missing", env_key)
    try:
        results = await refresh_feed_status_cache()
        for feed in results.get("feeds", []):
            state = "LIVE" if feed.get("auth_valid") else ("AUTH FAIL" if feed.get("reachable") else "OFFLINE")
            logger.info("  %s: %s", feed.get("name"), state)
    except Exception as exc:
        logger.warning("Initial feed probe failed: %s", exc)
    logger.info("=====================================")


@app.get("/api/v1/live-feeds/status")
async def live_feeds_status(probe: bool = False) -> dict:
    return threat_intel_engine.build_live_feed_status(probe=probe)


@app.get("/api/v1/feeds/probe")
async def probe_all_feeds(user: UserContext = Depends(get_current_user)) -> dict:
    return await refresh_feed_status_cache()


@app.get("/api/v1/feeds/status/live")
async def feeds_live_status(
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    if not _feed_status_cache.get("feeds"):
        return await refresh_feed_status_cache()
    background_tasks.add_task(refresh_feed_status_cache)
    return _feed_status_cache


@app.websocket("/api/v1/ws/feeds/status")
async def feeds_status_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            payload = await refresh_feed_status_cache()
            await websocket.send_json({
                "type": "feed_status",
                "timestamp": payload.get("timestamp"),
                "data": payload,
            })
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        return


@app.post("/api/v1/feeds/configure", dependencies=[Depends(require_roles("admin"))])
async def configure_feeds(payload: FeedConfigRequest, user: UserContext = Depends(get_current_user)) -> dict:
    if os.getenv("VERCEL"):
        raise HTTPException(
            status_code=501,
            detail="Feed configuration writes to .env are disabled on Vercel. Configure environment variables in the Vercel dashboard.",
        )
    env_path = BASE_DIR.parent / ".env"
    existing = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    key_map = {
        "alienvault_otx": "OTX_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "virustotal": "VIRUSTOTAL_API_KEY",
    }
    updates = {key_map[k]: v.strip() for k, v in payload.model_dump().items() if v and k in key_map}
    new_lines: List[str] = []
    updated: set[str] = set()
    for line in existing:
        if "=" not in line:
            new_lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            updated.add(key)
        elif key.startswith("RISKINTEL_") and key.replace("RISKINTEL_", "", 1) in updates:
            actual = key.replace("RISKINTEL_", "", 1)
            new_lines.append(f"{key}={updates[actual]}")
            updated.add(actual)
        else:
            new_lines.append(line)
    for key, value in updates.items():
        if key not in updated:
            new_lines.append(f"{key}={value}")
    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    for key, value in updates.items():
        os.environ[key] = value
        os.environ[f"RISKINTEL_{key}"] = value
    _reload_feed_keys()
    await refresh_feed_status_cache()
    case_store.audit(user.username, user.role, "configure_feeds", "feeds", meta={"updated": sorted(updates.keys())})
    return {"status": "ok", "updated": sorted(updates.keys())}


@app.get("/api/v1/auth/whoami")
async def whoami(user: UserContext = Depends(get_current_user)) -> dict:
    return {"authenticated": user.authenticated, "username": user.username, "role": user.role, "api_key_hash": user.api_key_hash}


# ─────────────────────────────────────────────────────
# Core analysis endpoints
# ─────────────────────────────────────────────────────
@app.post("/api/v1/analyze")
async def analyze(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    ck = _cache_key("analyze", payload.text[:500])
    cached = _get_cached(ck)
    if cached:
        return cached

    result, ioc_intel = await asyncio.gather(
        engine.analyze_async(payload.text),
        threat_intel_engine.scan_async(text=payload.text, live_feeds=_live_feeds_default()),
    )
    result["ioc_intelligence"] = ioc_intel
    _set_cached(ck, result)

    background_tasks.add_task(
        case_store.audit,
        actor=user.username, role=user.role, action="analyze_text", target_type="analysis",
        meta={"score": result.get("score"), "risk_level": result.get("risk_level"), "auth": user.authenticated},
    )
    return result


@app.post("/api/v1/analyze/batch")
async def analyze_batch(
    payload: BatchAnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    results = await engine.analyze_batch_async(payload.texts)
    background_tasks.add_task(
        case_store.audit, actor=user.username, role=user.role, action="analyze_batch",
        target_type="analysis", meta={"count": len(results), "auth": user.authenticated},
    )
    return {"count": len(results), "results": results}


@app.post("/api/v1/threat-intel")
async def threat_intel(
    payload: ThreatIntelRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    live = _live_feeds_default() if payload.live_feeds is None else bool(payload.live_feeds)
    result = await threat_intel_engine.scan_async(
        text=payload.text, urls=payload.urls, domains=payload.domains,
        ips=payload.ips, hashes=payload.hashes, live_feeds=live,
    )
    background_tasks.add_task(
        case_store.audit, actor=user.username, role=user.role, action="threat_intel_scan",
        target_type="intel", meta={"ioc_count": result.get("ioc_count", 0), "overall_risk": result.get("overall_risk")},
    )
    return result


@app.post("/api/v1/scamcheck")
async def scamcheck(payload: ScamCheckRequest) -> dict:
    return await scamcheck_service.check_async(payload.input, payload.detectedType)


@app.post("/api/v1/website-intel")
async def website_intel(payload: WebsiteIntelRequest) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(engine._executor, lambda: _build_website_scan_result(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/malware/analyze-file", response_model=FileAnalysisResult)
async def analyze_file(
    payload: FileAnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> FileAnalysisResult:
    try:
        blob = base64.b64decode(payload.content_base64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 file payload") from exc

    size_bytes = len(blob)
    sha256 = hashlib.sha256(blob).hexdigest()
    lowered = blob[:200000].lower()
    flags: List[str] = []
    score = 0

    if payload.filename.lower().endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta")):
        score += 35; flags.append("Executable/script extension")
    if blob.startswith(b"MZ"):
        score += 28; flags.append("PE header (MZ magic bytes)")
    if b"powershell" in lowered or b"cmd.exe" in lowered:
        score += 18; flags.append("Command execution string")
    if b"autoopen" in lowered or b"document_open" in lowered:
        score += 22; flags.append("Macro auto-execution pattern")
    if b"http://" in lowered or b"https://" in lowered:
        score += 10; flags.append("Embedded URL/network indicator")
    if size_bytes > 8_000_000:
        score += 6; flags.append("Large file size anomaly")
    if b"createobject" in lowered:
        score += 15; flags.append("CreateObject COM call (possible script malware)")
    if b"wscript.shell" in lowered:
        score += 20; flags.append("WScript.Shell execution")

    score = min(100, max(0, score))
    level = "critical" if score >= 80 else ("high" if score >= 55 else ("medium" if score >= 30 else "low"))

    file_ioc = await threat_intel_engine.scan_async(hashes=[sha256], live_feeds=_live_feeds_default())

    background_tasks.add_task(
        case_store.audit, actor=user.username, role=user.role, action="malware_file_analysis",
        target_type="file", target_id=payload.filename, meta={"size": size_bytes, "risk_score": score, "risk_level": level},
    )
    return FileAnalysisResult(
        filename=payload.filename, size_bytes=size_bytes, sha256=sha256,
        risk_score=score, risk_level=level, suspicious_signals=flags[:8], ioc_intelligence=file_ioc,
    )


@app.post("/api/v1/trace-website")
async def trace_website(
    payload: WebsiteTraceRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    ck = _cache_key("trace_website", payload.url, str(payload.max_pages), str(payload.max_depth))
    cached = _get_cached(ck)
    if cached:
        return cached

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            engine._executor,
            lambda: engine.trace_website(
                payload.url, max_pages=payload.max_pages, max_depth=payload.max_depth,
                include_external=payload.include_external, exhaustive=payload.exhaustive,
            ),
        )
        _set_cached(ck, result)
        background_tasks.add_task(
            case_store.audit, actor=user.username, role=user.role, action="trace_website",
            target_type="website", target_id=payload.url,
            meta={"site_verdict": result.get("site_verdict"), "pages_crawled": result.get("pages_crawled")},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/fusion-scan")
async def fusion_scan(
    payload: FusionScanRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    if not (payload.text and payload.text.strip()) and not (payload.website_url and payload.website_url.strip()):
        raise HTTPException(status_code=400, detail="Provide at least one of: text, website_url")
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            engine._executor,
            lambda: fusion_engine.fusion_scan(
                text=payload.text, website_url=payload.website_url,
                max_pages=payload.max_pages, max_depth=payload.max_depth,
                include_external=payload.include_external, exhaustive=payload.exhaustive,
            ),
        )
        if payload.text and payload.text.strip() and isinstance(result.get("text_analysis"), dict):
            ioc = await threat_intel_engine.scan_async(text=payload.text, live_feeds=_live_feeds_default())
            result["text_analysis"]["ioc_intelligence"] = ioc
        if payload.website_url and payload.website_url.strip():
            website_intel = await loop.run_in_executor(
                engine._executor,
                lambda: _build_website_scan_result(payload.website_url or ""),
            )
            result["website_intelligence"] = website_intel

        background_tasks.add_task(
            case_store.audit, actor=user.username, role=user.role, action="fusion_scan",
            target_type="platform", target_id=payload.website_url or "text-only",
            meta={"posture_score": result.get("posture_score"), "posture_state": result.get("posture_state")},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ─────────────────────────────────────────────────────
# Quick IOC lookup
# ─────────────────────────────────────────────────────
@app.get("/api/v1/ioc/{ioc_type}/{value}")
async def quick_ioc_lookup(
    ioc_type: str,
    value: str,
    live: bool = False,
    user: UserContext = Depends(get_current_user),
) -> dict:
    valid_types = {"domain", "ip", "url", "hash_md5", "hash_sha256", "hash_sha1"}
    if ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"ioc_type must be one of: {sorted(valid_types)}")
    result = await threat_intel_engine.scan_async(**{f"{ioc_type}s" if ioc_type != "url" else "urls": [value], "live_feeds": live})
    return result


# ─────────────────────────────────────────────────────
# Cache management
# ─────────────────────────────────────────────────────
@app.post("/api/v1/cache/clear", dependencies=[Depends(require_roles("admin"))])
async def clear_caches() -> dict:
    engine._global_link_cache.clear()
    engine._global_whois_cache.clear()
    engine._global_domain_cache.clear()
    engine._global_cert_cache.clear()
    engine._global_sitemap_cache.clear()
    threat_intel_engine._cache.clear()
    _response_cache.clear()
    return {"status": "cleared", "message": "All engine and response caches cleared."}


@app.get("/api/v1/cache/stats", dependencies=[Depends(require_roles("admin", "analyst"))])
async def cache_stats() -> dict:
    return {
        "engine": {
            "link_cache": len(engine._global_link_cache),
            "domain_cache": len(engine._global_domain_cache),
            "whois_cache": len(engine._global_whois_cache),
            "cert_cache": len(engine._global_cert_cache),
            "sitemap_cache": len(engine._global_sitemap_cache),
        },
        "threat_intel_cache": len(getattr(threat_intel_engine._cache, "_store", {})),
        "response_cache": len(_response_cache),
    }


# ─────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────
@app.get("/api/v1/metrics", dependencies=[Depends(require_roles("admin"))])
async def metrics() -> Response:
    lines = ["# HELP riskintel_requests_total Total requests per path",
             "# TYPE riskintel_requests_total counter"]
    for path, count in sorted(_request_counters.items()):
        safe_path = path.replace("/", "_").replace("-", "_").strip("_")
        lines.append(f'riskintel_requests_total{{path="{safe_path}"}} {count}')
    lines += [
        "",
        "# HELP riskintel_cache_size Cache sizes",
        "# TYPE riskintel_cache_size gauge",
        f'riskintel_cache_size{{name="link_cache"}} {len(engine._global_link_cache)}',
        f'riskintel_cache_size{{name="domain_cache"}} {len(engine._global_domain_cache)}',
        f'riskintel_cache_size{{name="threat_intel"}} {len(getattr(threat_intel_engine._cache, "_store", {}))}',
    ]
    return Response(content="\n".join(lines), media_type="text/plain")


# ─────────────────────────────────────────────────────
# Case management
# ─────────────────────────────────────────────────────
@app.post("/api/v1/cases", dependencies=[Depends(require_roles("admin", "analyst"))])
async def create_case(payload: CaseCreateRequest, user: UserContext = Depends(get_current_user)) -> dict:
    rec = case_store.create_case({
        "source_type": payload.source_type, "source_value": payload.source_value,
        "title": payload.title, "severity": payload.severity, "status": payload.status,
        "assigned_to": payload.assigned_to, "reporter": user.username,
        "findings": payload.findings, "tags": payload.tags, "recommendations": payload.recommendations,
        "ioc_type": payload.ioc_type, "ioc_value": payload.ioc_value, "risk_score": payload.risk_score,
        "scan_result": payload.scan_result, "notes": payload.notes,
    })
    case_store.audit(user.username, user.role, "create_case", "case", str(rec["id"]), {"severity": rec["severity"]})
    return rec


@app.post("/api/v1/cases/from-analysis", dependencies=[Depends(require_roles("admin", "analyst"))])
async def create_case_from_analysis(payload: CaseFromAnalysisRequest, user: UserContext = Depends(get_current_user)) -> dict:
    analysis = await engine.analyze_async(payload.text)
    rec = case_store.create_case({
        "source_type": "text", "source_value": payload.text[:300],
        "title": payload.title, "severity": analysis.get("risk_level", "medium"),
        "status": "new", "assigned_to": payload.assigned_to, "reporter": user.username,
        "findings": analysis, "tags": payload.tags, "recommendations": analysis.get("recommendations", []),
    })
    case_store.audit(user.username, user.role, "create_case_from_analysis", "case", str(rec["id"]),
                     {"risk_level": analysis.get("risk_level"), "score": analysis.get("score")})
    return rec


@app.get("/api/v1/cases")
async def list_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    rows = case_store.list_cases(status=status, severity=severity, assigned_to=assigned_to, limit=limit, search=search)
    case_store.audit(user.username, user.role, "list_cases", "case", meta={"count": len(rows)})
    return {"count": len(rows), "results": rows}


@app.get("/api/v1/cases/{case_id}")
async def get_case(case_id: int, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    try:
        rec = case_store.get_case(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "get_case", "case", str(case_id))
    return rec


@app.patch("/api/v1/cases/{case_id}", dependencies=[Depends(require_roles("admin", "analyst"))])
async def update_case(case_id: int, payload: CaseUpdateRequest, user: UserContext = Depends(get_current_user)) -> dict:
    try:
        rec = case_store.update_case(case_id, payload.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "update_case", "case", str(case_id), payload.model_dump())
    return rec


@app.delete("/api/v1/cases/{case_id}", dependencies=[Depends(require_roles("admin", "analyst"))], status_code=204)
async def delete_case(case_id: int, user: UserContext = Depends(get_current_user)) -> Response:
    try:
        case_store.delete_case(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "delete_case", "case", str(case_id))
    return Response(status_code=204)


@app.post("/api/v1/cases/{case_id}/comments", dependencies=[Depends(require_roles("admin", "analyst"))])
async def add_case_comment(case_id: int, payload: CommentCreateRequest, user: UserContext = Depends(get_current_user)) -> dict:
    try:
        comment = case_store.add_comment(case_id, user.username, payload.message)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "add_case_comment", "case", str(case_id))
    return comment


@app.get("/api/v1/audit", dependencies=[Depends(require_roles("admin"))])
async def list_audits(limit: int = 100, user: UserContext = Depends(get_current_user)) -> dict:
    rows = case_store.list_audits(limit=limit)
    case_store.audit(user.username, user.role, "list_audit_logs", "audit", meta={"count": len(rows)})
    return {"count": len(rows), "results": rows}

"""FastAPI server — REST API for PHANTOM detection platform.

Endpoints:
    POST /v1/analyze         — Run full detection pipeline on events
    POST /v1/sigma/evaluate  — Evaluate Sigma rules against events
    POST /v1/sigma/validate  — Validate a Sigma rule YAML
    POST /v1/sigma/generate  — Generate Sigma rule from natural language
    POST /v1/anomaly/detect  — Run anomaly detection on events
    GET  /v1/rules           — List loaded Sigma rules
    GET  /v1/coverage        — Get MITRE ATT&CK coverage report
    GET  /health             — Health check
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from phantom.engine import PhantomEngine

app = FastAPI(
    title="PHANTOM",
    description="AI-Powered Detection Engineering & Autonomous Threat Hunting Platform",
    version="0.1.0",
)

engine = PhantomEngine()


# --- Request/Response Models ---

class AnalyzeRequest(BaseModel):
    events: list[dict[str, Any]]
    run_hunting: bool = False

class AnalyzeResponse(BaseModel):
    total_detections: int
    incidents: int
    hunting_findings: int
    detections: list[dict[str, Any]]
    coverage: dict[str, Any]
    elapsed_seconds: float

class SigmaEvalRequest(BaseModel):
    events: list[dict[str, Any]]

class SigmaValidateRequest(BaseModel):
    rule_yaml: str

class SigmaGenerateRequest(BaseModel):
    description: str
    model: str = "claude-sonnet-4-20250514"

class AnomalyRequest(BaseModel):
    events: list[dict[str, Any]]


# --- Endpoints ---

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "phantom"}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """Run the full PHANTOM detection pipeline."""
    report = await engine.analyze(req.events, run_hunting=req.run_hunting)
    return AnalyzeResponse(
        total_detections=report.total_detections,
        incidents=len(report.incidents),
        hunting_findings=len(report.hunting_findings),
        detections=[
            {
                "rule_id": d.rule_id,
                "rule_name": d.rule_name,
                "severity": d.severity,
                "source": d.source,
                "mitre_techniques": d.mitre_techniques,
                "confidence": d.confidence,
                "matched_event_count": len(d.matched_events),
            }
            for d in report.detections
        ],
        coverage=report.coverage,
        elapsed_seconds=report.elapsed_seconds,
    )


@app.post("/v1/sigma/evaluate")
async def sigma_evaluate(req: SigmaEvalRequest) -> dict[str, Any]:
    """Evaluate loaded Sigma rules against events."""
    results = engine.sigma.evaluate(req.events)
    return {
        "detection_count": len(results),
        "detections": [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity,
                "matched_events": len(r.matched_events),
            }
            for r in results
        ],
    }


@app.post("/v1/sigma/validate")
async def sigma_validate(req: SigmaValidateRequest) -> dict[str, Any]:
    """Validate a Sigma rule YAML string."""
    valid, errors = engine.sigma.validate_rule(req.rule_yaml)
    return {"valid": valid, "errors": errors}


@app.post("/v1/sigma/generate")
async def sigma_generate(req: SigmaGenerateRequest) -> dict[str, Any]:
    """Generate a Sigma rule from natural language description."""
    try:
        rule_yaml = await engine.generate_rule(req.description, model=req.model)
        valid, errors = engine.sigma.validate_rule(rule_yaml)
        return {"rule_yaml": rule_yaml, "valid": valid, "errors": errors}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/anomaly/detect")
async def anomaly_detect(req: AnomalyRequest) -> dict[str, Any]:
    """Run anomaly detection on events."""
    normalized = engine.pipeline.normalize(req.events)
    results = engine.anomaly.detect(normalized)
    return {
        "anomaly_count": len(results),
        "anomalies": [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity,
                "confidence": r.confidence,
                "score": r.metadata.get("anomaly_score", 0),
            }
            for r in results
        ],
    }


@app.get("/v1/rules")
async def list_rules() -> dict[str, Any]:
    """List all loaded Sigma rules."""
    rules = engine.sigma.list_rules()
    return {"count": len(rules), "rules": rules}


@app.get("/v1/coverage")
async def coverage_report() -> dict[str, Any]:
    """Get MITRE ATT&CK coverage report for loaded rules."""
    techniques: list[str] = []
    for rule_info in engine.sigma.list_rules():
        techs = rule_info.get("techniques", "")
        if techs:
            techniques.extend(t.strip() for t in techs.split(",") if t.strip())
    return engine.mitre.coverage_report(techniques)

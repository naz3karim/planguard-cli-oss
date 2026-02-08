from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import Any, Dict

from policycheck.evaluator import evaluate

app = FastAPI(title="PolicyCheck API", version="0.2.0")

class EvaluateRequest(BaseModel):
    plan: Dict[str, Any]
    pack: str = "baseline"
    env: str = ""

@app.post("/v1/evaluate")
def evaluate_plan(req: EvaluateRequest):
    pack_dir = Path(f"controls/packs/{req.pack}")
    if not pack_dir.exists():
        raise HTTPException(status_code=400, detail=f"Unknown pack: {req.pack}")

    return evaluate(plan=req.plan, pack_dir=pack_dir, env=req.env)

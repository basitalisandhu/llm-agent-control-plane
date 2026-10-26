"""Token/cost ledger with hard caps per provider (USD). Prices per 1M tokens, Oct 2026 list prices."""
import json, os, threading, time
from pathlib import Path
PRICES = {  # input, cached-input, output
    "gpt-5.1": (1.25, 0.125, 10.0), "gpt-5": (1.25, 0.125, 10.0), "gpt-5-mini": (0.25, 0.025, 2.0), "gpt-5-nano": (0.05, 0.005, 0.4),
    "gpt-4.1": (2.0, 0.5, 8.0), "gpt-4.1-mini": (0.4, 0.1, 1.6), "gpt-4o": (2.5, 1.25, 10.0), "gpt-4o-mini": (0.15, 0.075, 0.6),
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0": (3.0, 0.3, 15.0), "us.anthropic.claude-haiku-4-5-20251001-v1:0": (1.0, 0.1, 5.0),
    "us.meta.llama3-3-70b-instruct-v1:0": (0.72, 0.72, 0.72),
}
CAPS = {"openai": float(os.environ.get("CAP_OPENAI", "120")), "bedrock": float(os.environ.get("CAP_BEDROCK", "150"))}
LEDGER = Path(os.environ.get("COST_LEDGER", "cost_ledger.jsonl"))
_lock = threading.Lock()

def price_key(model: str) -> str:
    for k in sorted(PRICES, key=len, reverse=True):
        if model.startswith(k): return k
    return model

def record(provider: str, model: str, inp: int, cached: int, out: int, tag: str = ""):
    p = PRICES.get(price_key(model), (3.0, 0.3, 15.0))
    cost = ((inp - cached) * p[0] + cached * p[1] + out * p[2]) / 1e6
    with _lock, LEDGER.open("a") as f:
        f.write(json.dumps({"t": time.time(), "provider": provider, "model": model, "in": inp, "cached": cached, "out": out, "usd": round(cost, 6), "tag": tag}) + "\n")
    return cost

def spent(provider: str) -> float:
    if not LEDGER.exists(): return 0.0
    return sum(json.loads(l)["usd"] for l in LEDGER.read_text().splitlines() if l and json.loads(l)["provider"] == provider)

def check_cap(provider: str):
    s = spent(provider)
    if s >= CAPS[provider]:
        raise RuntimeError(f"COST CAP REACHED for {provider}: ${s:.2f} >= ${CAPS[provider]:.2f}")
    return s

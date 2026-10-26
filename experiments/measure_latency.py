"""Times every PEP decision (provenance check plus any approval check) while the model-free replay of all 949 cases runs
(preflight_v22.py, matcher v2.2), and writes tex/results_latency.tex: median and 95th-percentile milliseconds per decision."""
import time, statistics, runpy, shutil, os, sys, filecmp
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pep22
times = []
_p, _a = pep22.PEPExecutor._provenance_check, pep22.PEPExecutor._approval_check
def wp(self, st, call):
    t0 = time.perf_counter(); r = _p(self, st, call); times.append(time.perf_counter() - t0); return r
def wa(self, *a, **k):
    t0 = time.perf_counter(); r = _a(self, *a, **k)
    if times: times[-1] += time.perf_counter() - t0
    return r
pep22.PEPExecutor._provenance_check, pep22.PEPExecutor._approval_check = wp, wa
had = os.path.exists("preflight_v22.json")
if had: shutil.copy("preflight_v22.json", "preflight_v22.json.bak")
t_wall = time.perf_counter(); runpy.run_path("preflight_v22.py", run_name="__main__"); t_wall = time.perf_counter() - t_wall
if had:
    same = filecmp.cmp("preflight_v22.json", "preflight_v22.json.bak", shallow=False)
    if not same: shutil.move("preflight_v22.json.bak", "preflight_v22.json"); print("WARNING: replay output differed; original restored")
    else: os.remove("preflight_v22.json.bak")
ms = sorted(t * 1000 for t in times); med = statistics.median(ms); p95 = ms[int(0.95 * len(ms)) - 1]
open("tex/results_latency.tex", "w").write(f"\\newcommand{{\\decisionMs}}{{{med:.2f}}}\n\\newcommand{{\\decisionMsNinetyFive}}{{{p95:.2f}}}\n\\newcommand{{\\nLatencyDecisions}}{{{len(ms):,}}}\n".replace(",", "\\,"))
print(f"decisions={len(ms):,} median={med:.3f} ms p95={p95:.3f} ms max={ms[-1]:.2f} ms; replay wall {t_wall:.0f} s")

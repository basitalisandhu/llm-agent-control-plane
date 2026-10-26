"""Make the research modules importable for the test suite without packaging them.

`pep/` holds the policy enforcement point, `experiments/` the replay harness that
`pep/test_write_labels.py` drives. Nothing here changes how the scripts run.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for sub in ("pep", "experiments"):
    path = str(ROOT / sub)
    if path not in sys.path:
        sys.path.insert(0, path)

from __future__ import annotations

import sys
from pathlib import Path

# The W3-04 eval harness and the AI-010 scorer live under scripts/ai-bakeoff,
# which is not a workspace package; put it on the path so `aieval` and `bakeoff`
# import exactly as the runners load them.
_BAKEOFF_ROOT = Path(__file__).resolve().parents[2] / "scripts" / "ai-bakeoff"
if str(_BAKEOFF_ROOT) not in sys.path:
    sys.path.insert(0, str(_BAKEOFF_ROOT))

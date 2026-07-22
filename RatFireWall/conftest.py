"""Make RatFireWall modules importable from tests without installation."""
import sys
from pathlib import Path

root = Path(__file__).parent.resolve()
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "HorridAPIResponseFirewall"))

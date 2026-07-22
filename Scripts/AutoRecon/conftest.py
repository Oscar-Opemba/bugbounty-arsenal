"""Make the AutoRecon modules importable from tests without installation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))

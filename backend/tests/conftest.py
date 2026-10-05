"""
Shared pytest setup for the PhishGuard regression suite.

predict_ml_only.py loads model.pkl / *_vectorizer.pkl / scaler.pkl with paths
that are RELATIVE TO THE CWD (open("model.pkl")). So every test must run with the
backend directory as the working directory. (main.py's blocklist path is now
anchored on its module dir, so it no longer depends on the CWD, but the model
artifacts still do.) We also put backend/ on sys.path so the test modules can
`import features`, `import main`, etc. regardless of where pytest was launched
from.
"""
import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Make the model artifacts + ../data/raw resolve, and make backend importable.
os.chdir(_BACKEND_DIR)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

"""Development entry point:  python run.py"""
import os
from pathlib import Path

from app import create_app

# Load a local .env if present (no extra dependency).
for candidate in (Path(__file__).parent / ".env", Path(__file__).parent.parent / ".env"):
    if candidate.exists():
        for line in candidate.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("CS_HOST", "127.0.0.1"), port=int(os.environ.get("CS_PORT", "5000")), debug=False,
            threaded=True)

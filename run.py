"""Development entry point: ``python run.py``."""
from __future__ import annotations

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # 127.0.0.1 by default: never expose a debug server to the network.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=app.config.get("DEBUG", False))

#!/usr/bin/env python3
"""Export Pydantic page-data models as JSON Schema for TypeScript generation."""
import json
from pathlib import Path

from datasette_auth_basic_login.page_data import __exports__

out_dir = Path("frontend/src/page_data")
out_dir.mkdir(parents=True, exist_ok=True)
for model in __exports__:
    out = out_dir / f"{model.__name__}_schema.json"
    out.write_text(json.dumps(model.model_json_schema(), indent=2))
    print(f"Wrote {out}")

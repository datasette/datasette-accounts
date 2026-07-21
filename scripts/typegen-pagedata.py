#!/usr/bin/env python3
"""Export Pydantic page-data models as JSON Schema for TypeScript generation."""

import json
from pathlib import Path

# Import Datasette first so its setuptools entry points load fully before we
# import this plugin package. Otherwise importing datasette_accounts standalone
# (which pulls datasette_user_profiles.hookspecs) can kick off plugin loading
# mid-initialisation and hit a circular import in sibling plugins (e.g. when
# datasette-paper is installed as a dev dependency).
import datasette.plugins  # noqa: F401

from datasette_accounts.page_data import __exports__

out_dir = Path("frontend/src/page_data")
out_dir.mkdir(parents=True, exist_ok=True)
for model in __exports__:
    out = out_dir / f"{model.__name__}_schema.json"
    out.write_text(json.dumps(model.model_json_schema(), indent=2))
    print(f"Wrote {out}")

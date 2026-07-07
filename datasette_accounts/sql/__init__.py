"""Generated SQL query helpers for datasette-accounts.

``queries.sql`` is the source of truth; ``_queries_generated.py`` (typed
helpers) is generated from it by ``just codegen-queries`` (via a gitignored
``_queries.sql.json`` codegen IR). ``db.py`` orchestrates these helpers inside
``execute_fn`` / ``execute_write_fn`` closures — do not hand-edit
``_queries_generated.py``.
"""

"""HTML page shells.

These are minimal, dependency-free server-rendered pages that drive the JSON
API via fetch(). Milestone M7 replaces them with the Svelte/Vite frontend
(the #pageData bootstrap and route contracts are already in place for that).
"""

import html
import json

from datasette import Response

from .. import db, security
from ..page_data import AccountPageData, AdminPageData, LoginPageData, UserRow
from ..router import require_admin_page, router

_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
  label { display:block; margin: .5rem 0 .2rem; font-weight: 600; }
  input { padding: .4rem; font-size: 1rem; min-width: 16rem; }
  button { padding: .4rem .8rem; font-size: 1rem; cursor: pointer; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { border: 1px solid #ccc; padding: .35rem .5rem; text-align: left; font-size: .9rem; }
  .msg { margin: .5rem 0; color: #b00; }
  .ok { color: #060; }
</style>
"""


def _page(title, body, page_data):
    return Response.html(
        f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(title)}</title>{_STYLE}
<script type="application/json" id="pageData">{json.dumps(page_data)}</script>
</head><body><div id="app-root">{body}</div></body></html>"""
    )


@router.GET("/-/login$")
async def login_page(datasette, request):
    next_value = security.validate_next(
        request.args.get("next"), datasette.setting("base_url") or "/"
    )
    page_data = LoginPageData(next=next_value).model_dump()
    body = """
<h1>Log in</h1>
<form id="f">
  <label>Username<input name="username" autocomplete="username" required></label>
  <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
  <p><button type="submit">Log in</button></p>
  <p class="msg" id="msg"></p>
</form>
<script>
const pd = JSON.parse(document.getElementById('pageData').textContent);
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const r = await fetch('/-/login/api/authenticate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: f.username.value, password: f.password.value, next: pd.next})
  });
  const j = await r.json();
  if (j.ok) { location = j.redirect || '/'; }
  else { document.getElementById('msg').textContent = j.error || 'Login failed'; }
});
</script>
"""
    return _page("Log in", body, page_data)


@router.GET("/-/logout$")
async def logout_page(datasette, request):
    # A GET page whose fetch() POSTs the logout (JSON, so the CSRF gate passes).
    # A bare GET must never destroy the session.
    body = """
<h1>Logging out…</h1>
<noscript><p>JavaScript is required to log out.</p></noscript>
<script>
fetch('/-/logout/perform', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'})
  .then(() => { location = '/'; });
</script>
"""
    return _page("Log out", body, {})


@router.GET("/-/account$")
async def account_page(datasette, request):
    if not request.actor:
        return Response.redirect(datasette.urls.path("/-/login?next=/-/account"))
    actor = request.actor
    page_data = AccountPageData(
        id=actor["id"],
        username=actor.get("username", ""),
        is_admin=bool(actor.get("is_admin")),
        must_change_password=bool(actor.get("must_change_password")),
    ).model_dump()
    forced = (
        '<p class="msg">You must change your password before continuing.</p>'
        if page_data["must_change_password"]
        else ""
    )
    body = f"""
<h1>Your account</h1>
<p>Signed in as <strong>{html.escape(page_data["username"])}</strong>.</p>
{forced}
<form id="f">
  <label>Current password<input name="current_password" type="password" required></label>
  <label>New password<input name="new_password" type="password" required></label>
  <p><button type="submit">Change password</button></p>
  <p class="msg" id="msg"></p>
</form>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {{
  e.preventDefault();
  const f = e.target;
  const r = await fetch('/-/account/api/change-password', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{current_password: f.current_password.value, new_password: f.new_password.value}})
  }});
  const j = await r.json();
  const m = document.getElementById('msg');
  if (j.ok) {{ m.className = 'ok'; m.textContent = 'Password changed.'; setTimeout(() => location = '/', 800); }}
  else {{ m.className = 'msg'; m.textContent = j.error || 'Failed'; }}
}});
</script>
"""
    return _page("Your account", body, page_data)


@router.GET("/-/admin/users$")
@require_admin_page
async def admin_page(datasette, request):
    internal = datasette.get_internal_database()
    rows = await db.list_users(internal)
    users = [
        UserRow(
            id=r["id"],
            username=r["username"],
            is_admin=bool(r["is_admin"]),
            disabled=bool(r["disabled"]),
            must_change_password=bool(r["must_change_password"]),
            locked=bool(r["locked_until"] and r["locked_until"] > db.now_iso()),
            created_at=r["created_at"],
        )
        for r in rows
    ]
    page_data = AdminPageData(users=users).model_dump()
    trows = "".join(
        f"<tr><td>{html.escape(u['username'])}</td>"
        f"<td>{'✓' if u['is_admin'] else ''}</td>"
        f"<td>{'disabled' if u['disabled'] else 'active'}</td>"
        f"<td>{'locked' if u['locked'] else ''}</td>"
        f"<td><code>{html.escape(u['id'])}</code></td></tr>"
        for u in page_data["users"]
    )
    body = f"""
<h1>Accounts</h1>
<form id="create">
  <label>New username<input name="username" required></label>
  <label>Initial password<input name="password" type="password" required></label>
  <label><input name="is_admin" type="checkbox"> Admin</label>
  <p><button type="submit">Create account</button></p>
  <p class="msg" id="msg"></p>
</form>
<table><thead><tr><th>Username</th><th>Admin</th><th>Status</th><th>Lock</th><th>id</th></tr></thead>
<tbody>{trows}</tbody></table>
<script>
document.getElementById('create').addEventListener('submit', async (e) => {{
  e.preventDefault();
  const f = e.target;
  const r = await fetch('/-/admin/api/create', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{username: f.username.value, password: f.password.value, is_admin: f.is_admin.checked}})
  }});
  const j = await r.json();
  if (j.ok) {{ location.reload(); }}
  else {{ document.getElementById('msg').textContent = j.error || 'Failed'; }}
}});
</script>
"""
    return _page("Accounts", body, page_data)

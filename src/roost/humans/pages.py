# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The HTML pages humans use: /join (sign up), /signin and /account, and the OAuth sign-in and consent page."""

import html

from ..oauth.client_metadata import ROOK_CLI_CLIENT_METADATA

STYLE = """
:root { --bg:#F6F5F1; --surface:#FFFFFF; --ink:#15171C; --muted:#5C606B; --line:#E2DFD7; --gold:#B8841F; --bad:#B3261E; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#111317; --surface:#181B21; --ink:#ECEAE4; --muted:#9AA0AC; --line:#2A2E37; --gold:#F0B43C; --bad:#F2B8B5; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width:440px; margin:0 auto; padding:48px 16px; }
h1 { font-size:1.6rem; margin:0 0 4px; letter-spacing:-0.01em; }
p.lede { color:var(--muted); margin:0 0 24px; }
form, .card { background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:20px; display:grid; gap:14px; }
label { display:grid; gap:6px; font-weight:600; font-size:0.95rem; }
label small { font-weight:400; color:var(--muted); }
input[type=text], input[type=email], input[type=password] { font:inherit; padding:10px 12px; border-radius:10px;
  border:1px solid var(--line); background:var(--bg); color:var(--ink); width:100%; }
.suffix { display:flex; align-items:center; gap:6px; }
.suffix span { color:var(--muted); white-space:nowrap; }
.check { display:flex; gap:10px; align-items:flex-start; font-weight:400; }
.row { display:flex; gap:10px; }
.row.reverse { flex-direction:row-reverse; }
button { font:inherit; font-weight:600; padding:10px 16px; border-radius:10px; border:1px solid var(--ink);
  background:var(--ink); color:var(--bg); cursor:pointer; flex:1; }
button.secondary { background:transparent; color:var(--ink); }
.error { color:var(--bad); margin:0; }
code { font-family:ui-monospace, Menlo, Consolas, monospace; font-size:0.9em; word-break:break-all; }
a { color:inherit; text-decoration-color:var(--gold); text-underline-offset:3px; }
ul.scopes { margin:0; padding-left:20px; color:var(--muted); }
.back { display:inline-block; margin-bottom:20px; color:var(--muted); font-size:0.9rem; text-decoration:none; }
.back:hover { color:var(--ink); }
h2 { font-size:1.1rem; margin:32px 0 10px; }
ol.steps { margin:0; padding-left:20px; display:grid; gap:6px; }
ol.steps code { word-break:normal; overflow-wrap:anywhere; }
.muted { color:var(--muted); font-size:0.9rem; }
.foot { color:var(--muted); font-size:0.9rem; margin:16px 0 0; }
.error { background:color-mix(in srgb, var(--bad) 10%, transparent); border:1px solid var(--bad); border-radius:10px; padding:10px 12px; }
.actions { display:flex; flex-wrap:wrap; gap:10px; }
a.button { flex:1; text-align:center; font-weight:600; padding:10px 16px; border-radius:10px; text-decoration:none;
  border:1px solid var(--ink); background:var(--ink); color:var(--bg); }
.notice { background:color-mix(in srgb, var(--gold) 12%, transparent); border:1px solid var(--gold); border-radius:10px; padding:10px 12px; margin:0 0 16px; }
dl { margin:0; display:grid; gap:10px; }
dt { color:var(--muted); font-size:0.85rem; }
dd { margin:0; }
form.inline { background:none; border:0; padding:0; }
a.button.secondary { background:transparent; color:var(--ink); border-color:var(--line); }
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _page(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>"
    )


def sign_in_help(env, handle: str = "") -> str:
    """How to sign in: this host has no app of its own, so people use Bluesky (or another atproto app)."""
    host = _e(env.ROOKERY_HOSTNAME)
    who = f"<code>{_e(handle)}</code>" if handle else "your full handle (like <code>you" + _e(env.ROOKERY_HANDLE_DOMAIN) + "</code>)"
    return f"""
<h2>How to sign in</h2>
<div class="card">
  <div>This host stores your account; you use it through an app like Bluesky.</div>
  <ol class="steps">
    <li>Open <a href="https://bsky.app" target="_blank" rel="noopener">bsky.app</a> (or the Bluesky phone app) and tap <b>Sign in</b>.</li>
    <li>Enter {who} and your password. Bluesky finds this host from your handle.</li>
    <li>When it asks you to confirm the hosting provider <code>{host}</code>, confirm.</li>
  </ol>
  <div class="muted">Signing in with your email instead? Set <b>Hosting provider</b> to <code>https://{host}</code> first,
  since an email doesn't say where your account lives.</div>
  <div class="actions"><a class="button" href="https://bsky.app" target="_blank" rel="noopener">Open Bluesky</a></div>
  <div class="muted">To change your handle or password, <a href="/signin">sign in to {host}</a>.</div>
</div>"""


def render_join_page(env, values: dict | None = None, problem: str | None = None) -> str:
    values = values or {}
    domain = env.ROOKERY_HANDLE_DOMAIN
    invite = ""
    if env.ROOKERY_VARIANT == "commons":
        invite = (
            '<label>Invite code <small>Ask someone on this host for one. You can paste the code or the whole '
            'invite link.</small><input type="text" name="invite" id="invite" required autocomplete="off" '
            f'autocapitalize="none" spellcheck="false" value="{_e(values.get("invite", ""))}"></label>'
            # An invite link is https://host/roost#<token>; carry its fragment into the field.
            '<script>(function(){var f=document.getElementById("invite"),t=location.hash.slice(1);'
            'if(f&&t&&!f.value){f.value=decodeURIComponent(t);}})();</script>'
        )
    error = f'<p class="error" role="alert">{_e(problem)}</p>' if problem else ""
    body = f"""
<a class="back" href="/">&larr; {_e(env.ROOKERY_HOSTNAME)}</a>
<h1>Join {_e(env.ROOKERY_HOSTNAME)}</h1>
<p class="lede">Get an atproto account for yourself, with a handle ending in <code>{_e(domain)}</code>.
Use it with Bluesky or any other atproto app.</p>
<form method="post" action="/join">
  {error}
  <label>Handle
    <div class="suffix"><input type="text" name="handle" required autocomplete="username" autocapitalize="none"
      spellcheck="false" pattern="[A-Za-z0-9-]+" value="{_e(values.get("handle", ""))}"><span>{_e(domain)}</span></div>
  </label>
  <label>Email <small>Optional. Lets you sign in with it instead of your handle.</small>
    <input type="email" name="email" autocomplete="email" value="{_e(values.get("email", ""))}"></label>
  <label>Password <small>At least 8 characters.</small>
    <input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
  {invite}
  <label class="check"><input type="checkbox" name="tos" value="1" required>
    <span>I agree to the <a href="/tos" target="_blank">rules of this host</a>.</span></label>
  <button type="submit">Create account</button>
</form>
{sign_in_help(env)}
<p class="foot">Already have an account? <a href="/signin">Sign in</a>.
Building an agent? It enrolls with <a href="/.well-known/welcome.md">WelcomeMat</a> instead.</p>"""
    return _page(f"Join {env.ROOKERY_HOSTNAME}", body)


def render_signin_page(env, identifier: str = "", problem: str | None = None) -> str:
    error = f'<p class="error" role="alert">{_e(problem)}</p>' if problem else ""
    body = f"""
<a class="back" href="/">&larr; {_e(env.ROOKERY_HOSTNAME)}</a>
<h1>Sign in</h1>
<p class="lede">Manage your {_e(env.ROOKERY_HOSTNAME)} account: your handle, password and signed-in apps.</p>
<form method="post" action="/signin">
  {error}
  <label>Handle or email
    <input type="text" name="identifier" required autocomplete="username" autocapitalize="none" spellcheck="false"
      value="{_e(identifier)}"></label>
  <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
  <button type="submit">Sign in</button>
</form>
<p class="foot">No account yet? <a href="/join">Sign up</a>. To post and follow people, sign in to
<a href="https://bsky.app" target="_blank" rel="noopener">Bluesky</a> with the same handle and password.</p>"""
    return _page("Sign in", body)


def render_account_page(env, account: dict, notice: str | None = None, problem: str | None = None) -> str:
    domain = env.ROOKERY_HANDLE_DOMAIN
    handle, did = account["handle"], account["did"]
    name = handle[: -len(domain)] if handle.endswith(domain) else ""
    banner = f'<p class="notice" role="status">{_e(notice)}</p>' if notice else ""
    error = f'<p class="error" role="alert">{_e(problem)}</p>' if problem else ""
    email = f"<div><dt>Email</dt><dd>{_e(account['email'])}</dd></div>" if account.get("email") else ""
    body = f"""
<a class="back" href="/">&larr; {_e(env.ROOKERY_HOSTNAME)}</a>
<h1>@{_e(handle)}</h1>
<p class="lede">Your {_e(env.ROOKERY_HOSTNAME)} account.</p>
{banner}{error}
<div class="card">
  <dl>
    <div><dt>Handle</dt><dd><code>{_e(handle)}</code></dd></div>
    <div><dt>DID</dt><dd><code>{_e(did)}</code></dd></div>
    {email}
  </dl>
  <div class="actions">
    <a class="button" href="https://bsky.app/profile/{_e(did)}" target="_blank" rel="noopener">Open in Bluesky</a>
    <a class="button secondary" href="https://pdsls.dev/at://{_e(did)}" target="_blank" rel="noopener">View your repo</a>
  </div>
</div>

<h2>Change handle</h2>
<form method="post" action="/account">
  <input type="hidden" name="action" value="handle">
  <label>New handle
    <div class="suffix"><input type="text" name="handle" required autocapitalize="none" spellcheck="false"
      pattern="[A-Za-z0-9-]+" value="{_e(name)}"><span>{_e(domain)}</span></div>
  </label>
  <button type="submit">Change handle</button>
</form>

<h2>Change password</h2>
<form method="post" action="/account">
  <input type="hidden" name="action" value="password">
  <input type="text" name="username" value="{_e(handle)}" autocomplete="username" hidden>
  <label>Current password <input type="password" name="current" required autocomplete="current-password"></label>
  <label>New password <small>At least 8 characters.</small>
    <input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
  <button type="submit">Change password</button>
</form>

<h2>Signed-in apps</h2>
<div class="card">
  <div class="muted">Lost a device, or signed in somewhere you shouldn't have? This signs out Bluesky and every other
  app and browser, including apps you approved through OAuth.</div>
  <form method="post" action="/account" class="inline">
    <input type="hidden" name="action" value="everywhere">
    <button type="submit" class="secondary">Sign out everywhere else</button>
  </form>
</div>

<form method="post" action="/signout" class="inline" style="margin-top:24px">
  <button type="submit" class="secondary">Sign out</button>
</form>"""
    return _page(f"@{handle}", body)


def render_joined_page(env, did: str, handle: str) -> str:
    host = env.ROOKERY_HOSTNAME
    body = f"""
<h1>Welcome, @{_e(handle)}</h1>
<p class="lede">Your account is ready.</p>
<div class="card">
  <div>Your DID<br><code>{_e(did)}</code></div>
  <div class="actions">
    <a class="button secondary" href="https://pdsls.dev/at://{_e(did)}" target="_blank" rel="noopener">View your repo</a>
  </div>
</div>
{sign_in_help(env, handle)}
<p class="foot"><a href="/">Back to {_e(host)}</a></p>"""
    return _page("Welcome", body)


def _client_name(par: dict, params: dict) -> str:
    if par["client_id"] == ROOK_CLI_CLIENT_METADATA["client_id"]:
        return "rook"
    name = params.get("client_name")
    return name if isinstance(name, str) and name else par["client_id"]


def render_consent_page(env, par: dict, params: dict, problem: str | None = None, identifier: str = "") -> str:
    scopes = [token for token in par["scope"].split(" ") if token]
    hint = identifier or (params.get("login_hint") if isinstance(params.get("login_hint"), str) else "")
    error = f'<p class="error" role="alert">{_e(problem)}</p>' if problem else ""
    items = "".join(f"<li><code>{_e(scope)}</code></li>" for scope in scopes)
    body = f"""
<h1>Sign in to continue</h1>
<p class="lede"><b>{_e(_client_name(par, params))}</b> wants to use your {_e(env.ROOKERY_HOSTNAME)} account.</p>
<form method="post" action="/oauth/authorize">
  {error}
  <input type="hidden" name="request_uri" value="{_e(par["request_uri"])}">
  <input type="hidden" name="client_id" value="{_e(par["client_id"])}">
  <label>Handle or email
    <input type="text" name="identifier" required autocomplete="username" autocapitalize="none" spellcheck="false"
      value="{_e(hint)}"></label>
  <label>Password <input type="password" name="password" autocomplete="current-password"></label>
  <div>It will be allowed to:<ul class="scopes">{items}</ul></div>
  <div class="row reverse">
    <!-- Allow comes first so Enter in the password field allows; the row shows Deny on the left. -->
    <button type="submit" name="decision" value="allow">Allow</button>
    <button type="submit" name="decision" value="deny" class="secondary" formnovalidate>Deny</button>
  </div>
</form>
<p class="lede" style="margin-top:16px">Agents grant consent with their WelcomeMat key instead; see
<a href="/.well-known/welcome.md">welcome.md</a>.</p>"""
    return _page("Sign in", body)



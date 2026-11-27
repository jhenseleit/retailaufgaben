#!/usr/bin/env python3
"""Skyport Werkbank - gemeinsame Anmeldung (SSO) + Passwort-Verwaltung.

EIN auth.py für ALLE Werkbank-Services (Portal + Module). Diese Datei ist in
jedem Repo identisch.

Portal (WERKBANK_PORTAL=1):
  Zentrale Anmeldung. Bedient /login, /logout, /setup und /konto selbst (in der
  Middleware). Passwörter werden NUR gehasht im Volume (DATA_DIR) gespeichert.
  /konto ist die Passwort-Verwaltung für den Admin. /setup ist die
  Erst-Einrichtung, solange noch kein Admin-Passwort existiert (Token steht beim
  Start in den Server-Logs).

Module (Standard, ohne WERKBANK_PORTAL):
  Pruefen nur den gemeinsamen Session-Cookie. Laeuft der Request unter der
  gemeinsamen Domain (COOKIE_DOMAIN) und ist PORTAL_URL gesetzt, werden nicht
  angemeldete Nutzer zum Portal-Login geschickt und danach zurück (?next=).
  Solange ein Service noch unter *.sliplane.app laeuft, greift ein lokaler
  Fallback-Login (Env-Passwort), damit nichts bricht.

Der Session-Cookie ist mit AUTH_SECRET signiert (in ALLEN Services identisch) und
wird auf COOKIE_DOMAIN gesetzt, sobald der Request unter dieser Domain laeuft -
dadurch teilen sich alle Module dieselbe Anmeldung.

Kompatibel zur bisherigen Schnittstelle: app.py der Module ruft weiterhin
get_current_user, user_header_html, login_page_html, authenticate, create_token,
COOKIE_NAME, SESSION_HOURS, auth_middleware - die app.py-Dateien muessen NICHT
geändert werden.

Umgebungsvariablen:
    AUTH_SECRET     Signierschluessel (ueberall identisch, geheim)
    ADMIN_EMAIL / RETAIL_EMAIL   Login-Adressen
    ADMIN_PASS / RETAIL_PASS     optionales Bootstrap-Passwort (Fallback)
    SESSION_HOURS   Gueltigkeit der Anmeldung in Stunden (Standard 12)
    COOKIE_DOMAIN   gemeinsame Cookie-Domain für SSO (z. B. .werkbank.skyport-group.de)
    WERKBANK_PORTAL =1 nur im Portal-Service
    PORTAL_URL      Basis-URL des Portals (z. B. https://werkbank.skyport-group.de)
    DATA_DIR        Passwort-Speicher (nur Portal; Standard /data)
    APP_NAME        Anzeigename für die Login-Seite (optional)
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from html import escape
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi.responses import HTMLResponse, RedirectResponse, Response

# ─── Konfiguration ──────────────────────────────────────────────────────────
COOKIE_NAME = "werkbank_session"
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "12"))
_SECRET = (os.environ.get("AUTH_SECRET") or "dev-only-insecure-secret").encode()

IS_PORTAL = os.environ.get("WERKBANK_PORTAL", "").strip().lower() not in ("", "0", "false", "no")
# Portal-Adresse für die Anmeldung. Eine eigene Domain (werkbank.skyport-group.de)
# ist noch nicht live - deshalb gilt ein gesetztes PORTAL_URL nur, wenn es auf
# *.sliplane.app (oder lokal) zeigt; sonst die bekannte Übersicht.
_PORTAL_ENV = (os.environ.get("PORTAL_URL", "") or "").strip().rstrip("/")
PORTAL_URL = (_PORTAL_ENV if any(x in _PORTAL_ENV for x in (".sliplane.app", "localhost", "127.0.0.1"))
              else ("" if IS_PORTAL else "https://skyport-werkbank.sliplane.app"))
COOKIE_DOMAIN = (os.environ.get("COOKIE_DOMAIN", "") or "").strip() or None
_DOMAIN_ROOT = COOKIE_DOMAIN.lstrip(".") if COOKIE_DOMAIN else None
APP_NAME = os.environ.get("APP_NAME", "Skyport Werkbank")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
PW_STORE = DATA_DIR / "werkbank_auth.json"
_ROLE_PASS_ENV = {"admin": "ADMIN_PASS", "retail": "RETAIL_PASS"}
_PBKDF2_ROUNDS = 200_000
MIN_PW_LEN = 8

# Ohne Anmeldung erreichbar (Healthcheck der Plattform).
PUBLIC_PATHS = {"/health", "/favicon.ico"}

# ─── Werkzeug-Navigation (obere Leiste) ─────────────────────────────────────
# EINE zentrale Quelle für die Navigationsleiste aller Module. Reihenfolge =
# Anzeigereihenfolge. admin_only=True -> Eintrag nur für Rolle "admin".
# Die Module liefern nur einen leeren/alten <nav class="switch">…</nav>-Block;
# die Middleware ersetzt ihn zentral und rollenabhaengig (siehe _serve/nav_html).
# (URLs bleiben *.sliplane.app, bis DNS auf *.werkbank.skyport-group.de steht.)
# Kurze Nav-Labels, damit alle 6 Eintraege + Marke + Nutzerzeile in EINE Zeile
# passen (die vollen Namen stehen als Ueberschrift auf der jeweiligen Zielseite).
NAV_TOOLS = [
    ("portal",     "&Uuml;bersicht", "https://skyport-werkbank.sliplane.app",           False),
    ("hfn",        "HFN",            "https://hfn-bestellanlage.sliplane.app",          False),
    ("viking",     "Viking",         "https://viking-bestand.sliplane.app",             False),
    ("cb",         "CB-Web",         "https://cb-web-bestellanlage-lager.sliplane.app", False),
    ("wayfair",    "Versandlabels",  "https://wayfair-versandlabels.sliplane.app",      False),
    ("avis",       "Avis",           "https://avis-konverter.sliplane.app",             False),
    ("deltav",     "Delta-V",        "https://deltav-bestandsmeldung.sliplane.app",     False),
    ("rechner",    "Direktlieferung", "https://containerpreisrechner.sliplane.app",     True),
    ("sortiment",  "Sortiment",      "https://sortimentsabgleich.sliplane.app",         True),
    ("schweiz",    "Schweiz Export", "https://schweiz-export.sliplane.app",             False),
    ("stammdaten", "Stammdaten",     "https://haendler-stammdaten.sliplane.app/admin",  True),
]

# ─── Einmal anmelden (SSO über die Übersicht) ───────────────────────────────
# Jedes Werkzeug läuft unter einer eigenen *.sliplane.app-Adresse; Cookies
# lassen sich dort nicht teilen. Deshalb meldet man sich NUR im Portal an.
# Jeder Klick auf eine Kachel oder einen Nav-Eintrag läuft über
# PORTAL_URL/go?to=<Ziel>. Das Portal hängt ein kurzlebiges, signiertes Ticket
# an (Ziel/sso?t=…); das Werkzeug prüft es mit dem gemeinsamen AUTH_SECRET und
# setzt seinen eigenen Session-Cookie (gleiches Ablaufdatum wie im Portal).
# Wer ein Werkzeug ohne Anmeldung öffnet, landet beim Portal-Login und kommt
# danach automatisch zurück. Tickets gibt es nur für die Hosts unten, und für
# Nur-Admin-Werkzeuge nur an die Rolle "admin".
SSO_EXTRA = [
    ("kundenkompass",  "https://kundenkompass.sliplane.app",         True),
    ("branchenradar",  "https://branchenradar.sliplane.app",         True),
    ("retailaufgaben", "https://retailaufgaben.sliplane.app",        False),
    ("kundenanalyse",  "https://skyport-kundenanalyse.sliplane.app", True),
]
TICKET_SECONDS = 120
_TICKET_KEY = hmac.new(_SECRET, b"werkbank-sso-ticket", hashlib.sha256).digest()


def _sso_hosts():
    """Hostname -> admin_only für alle Werkzeuge, die ein Ticket bekommen dürfen."""
    hosts = {}
    rows = [(u, a) for _k, _l, u, a in NAV_TOOLS if _k != "portal"]
    rows += [(u, a) for _k, u, a in SSO_EXTRA]
    for url, admin_only in rows:
        h = (urlparse(url).hostname or "").lower()
        if h:
            hosts[h] = hosts.get(h, False) or admin_only
    for h in os.environ.get("SSO_HOSTS", "").split(","):  # z. B. lokale Tests
        h = h.strip().lower()
        if h:
            hosts.setdefault(h, False)
    return hosts


def _b64e(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()


def _ticket_sig(payload):
    return hmac.new(_TICKET_KEY, payload.encode(), hashlib.sha256).hexdigest()


def create_ticket(user, host, session_exp):
    exp = int(time.time()) + TICKET_SECONDS
    payload = "|".join(("sso", user["email"], user["role"], str(int(session_exp)),
                        host.lower(), str(exp)))
    return _b64e(payload) + "." + _ticket_sig(payload)


def verify_ticket(ticket, host):
    try:
        b, sig = (ticket or "").rsplit(".", 1)
        payload = _b64d(b)
        tag, email, role, sess_exp, t_host, exp = payload.split("|")
        now = int(time.time())
        if tag != "sso" or not hmac.compare_digest(_ticket_sig(payload), sig):
            return None
        if int(exp) < now or int(sess_exp) < now or t_host != (host or "").lower():
            return None
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    if role not in ("admin", "retail"):
        return None
    return {"email": email, "role": role, "exp": int(sess_exp)}


def portal_link(url):
    """Kachel-/Nav-Link: über PORTAL/go, wenn das Ziel SSO kann, sonst unverändert."""
    h = (urlparse(url).hostname or "").lower()
    if h not in _sso_hosts():
        return url
    return ("" if IS_PORTAL else PORTAL_URL) + "/go?to=" + quote(url, safe="")


def _sso_target(to, user, request):
    """Ticket-URL für ein erlaubtes Werkzeug - sonst None."""
    try:
        p = urlparse(to or "")
        port = p.port
    except ValueError:
        return None
    h = (p.hostname or "").lower()
    hosts = _sso_hosts()
    if p.scheme not in ("http", "https") or h not in hosts:
        return None
    if hosts[h] and user.get("role") != "admin":
        return None
    try:
        sess_exp = int(request.cookies.get(COOKIE_NAME, "").rsplit("|", 3)[2])
    except (ValueError, IndexError):
        sess_exp = int(time.time()) + SESSION_HOURS * 3600
    local = h in ("localhost", "127.0.0.1")
    scheme = p.scheme if local else "https"
    netloc = h + (":" + str(port) if port else "")
    nxt = (p.path or "/") + (("?" + p.query) if p.query else "")
    return (scheme + "://" + netloc + "/sso?t=" + quote(create_ticket(user, h, sess_exp))
            + "&next=" + quote(nxt, safe=""))


def _go_handler(request):
    """Portal: angemeldeten Nutzer mit Ticket ins Werkzeug weiterreichen."""
    to = request.query_params.get("to", "")
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login?next=" + quote("/go?to=" + quote(to, safe=""), safe=""),
                                status_code=303)
    return RedirectResponse(_sso_target(to, user, request) or "/", status_code=303)


def _self_base(request):
    h = request.headers.get("host") or request.url.netloc
    local = h.split(":")[0] in ("localhost", "127.0.0.1")
    return (request.url.scheme if local else "https") + "://" + h


def _rel(nxt):
    return nxt if (nxt and nxt.startswith("/") and not nxt.startswith("//")) else None


def _to_portal_login(request, nxt=None):
    """Modul: nicht angemeldet -> Portal-Login, danach zurück an dieselbe Stelle."""
    if nxt is None:
        nxt = request.url.path + (("?" + request.url.query) if request.url.query else "")
    return RedirectResponse(PORTAL_URL + "/login?next=" + quote(_self_base(request) + nxt, safe=""),
                            status_code=303)


def login_path(request):
    """Für eigene Middlewares: /login mit Rücksprung an die aktuelle Seite."""
    q = ("?" + request.url.query) if request.url.query else ""
    return "/login?next=" + quote(request.url.path + q, safe="")


def _sso_handler(request):
    """Modul: Ticket aus dem Portal einlösen -> eigener Session-Cookie."""
    user = verify_ticket(request.query_params.get("t", ""), _host(request))
    nxt = _rel(request.query_params.get("next")) or "/"
    if not user:
        return HTMLResponse(login_page_html(
            APP_NAME, error="Die automatische Anmeldung hat nicht geklappt. Bitte "
                            "hier anmelden oder das Werkzeug erneut über die Übersicht öffnen.",
            next_url=nxt), status_code=401)
    resp = RedirectResponse(nxt, status_code=303)
    _set_session_cookie(resp, request, create_token(user["email"], user["role"], exp=user["exp"]))
    return resp


async def sso_gate(request, call_next):
    """Für Werkzeuge mit EIGENER Zugangs-Middleware (statt auth_middleware):
    als äußerste Middleware registrieren. Löst Tickets ein, schickt /login zum
    Portal und meldet beim Abmelden auch im Portal ab."""
    path = request.url.path
    if IS_PORTAL:
        return await call_next(request)
    if path == "/sso":
        return _sso_handler(request)
    if path == "/logout":
        return _do_logout(request)
    if (path == "/login" and request.method in ("GET", "HEAD") and PORTAL_URL
            and not request.query_params.get("lokal")):
        nxt = _rel(request.query_params.get("next"))
        if get_current_user(request):
            return RedirectResponse(nxt or "/", status_code=303)
        return _to_portal_login(request, nxt or "/")
    return await call_next(request)


# Erkennt anhand des Hosts den aktiven Nav-Eintrag (Regex-Ersatz der Leiste).
_NAV_RE = re.compile(r'<nav class="switch"[^>]*>.*?</nav>', re.DOTALL)

# Zentrales Styling der Navigationsleiste. Wird zusammen mit der Leiste in JEDE
# Modulseite eingesetzt und ueberschreibt (per !important) evtl. abweichendes
# lokales .switch-CSS - so sieht die Leiste in allen Modulen identisch aus:
# eine kompakte, einzeilige Reihe (bei Bedarf horizontal scrollbar statt Umbruch).
NAV_STYLE = (
    "<style>"
    ".switch{display:flex!important;flex-wrap:nowrap!important;align-items:center!important;"
    "gap:2px!important;overflow-x:auto!important;scrollbar-width:none!important;-ms-overflow-style:none!important}"
    ".switch::-webkit-scrollbar{display:none!important}"
    ".switch a{color:var(--text-secondary,#58616e)!important;text-decoration:none!important;font-size:14px!important;"
    "font-weight:500!important;letter-spacing:0!important;text-transform:none!important;white-space:nowrap!important;"
    "padding:8px 12px!important;border:0!important;border-radius:6px!important;background:none!important;transition:.15s!important}"
    ".switch a:hover{color:var(--ink,#151a21)!important;background:var(--gray-100,#f1f5f9)!important}"
    ".switch a.on{color:var(--accent-active,#3730a3)!important;background:var(--accent-soft,#eef1fe)!important}"
    "</style>"
)


# ─── Passwort-Speicher (nur das Portal nutzt das Volume) ────────────────────
def role_emails():
    """role -> E-Mail (aus Umgebungsvariablen; nicht geheim)."""
    emails = {}
    for prefix, role in (("ADMIN", "admin"), ("RETAIL", "retail")):
        email = os.environ.get(prefix + "_EMAIL", "").strip().lower()
        if email:
            emails[role] = email
    return emails


def _load_store():
    try:
        return json.loads(PW_STORE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_store(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PW_STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(PW_STORE)


def _hash_pw(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", (password or "").encode(), bytes.fromhex(salt_hex), _PBKDF2_ROUNDS
    ).hex()


def set_password(role, new_password):
    """Setzt (gehasht) das Passwort für 'admin' oder 'retail'."""
    if role not in ("admin", "retail"):
        raise ValueError("unbekannte Rolle")
    if not new_password or len(new_password) < MIN_PW_LEN:
        raise ValueError(f"Passwort muss mindestens {MIN_PW_LEN} Zeichen haben.")
    data = _load_store()
    salt = secrets.token_hex(16)
    data[role] = {"salt": salt, "hash": _hash_pw(new_password, salt)}
    _save_store(data)


def _check_stored(role, password):
    rec = _load_store().get(role)
    if not rec:
        return None
    return hmac.compare_digest(rec["hash"], _hash_pw(password, rec["salt"]))


def _env_pass(role):
    return os.environ.get(_ROLE_PASS_ENV.get(role, ""), "")


def password_configured(role):
    return role in _load_store() or bool(_env_pass(role))


def needs_setup():
    """Erst-Einrichtung noetig, wenn der Admin noch kein Passwort hat."""
    return not password_configured("admin")


_setup_token = None


def setup_token():
    global _setup_token
    if _setup_token is None:
        _setup_token = secrets.token_urlsafe(24)
    return _setup_token


def check_setup_token(token):
    return bool(token) and hmac.compare_digest(token, setup_token())


# ─── Audit-Log (best effort; darf die Verarbeitung NIE stoeren) ─────────────────

def get_audit_log(db_path, limit=30):
    """Letzte Audit-Eintraege, neueste zuerst. Liefert [] bei jedem Fehler."""
    try:
        con = sqlite3.connect(db_path, timeout=5)
        cur = con.execute(
            'SELECT ts, email, role, action, detail FROM audit ORDER BY rowid DESC LIMIT ?',
            (int(limit),))
        rows = [{'timestamp': r[0] or '', 'email': r[1] or '', 'role': r[2] or '',
                 'action': r[3] or '', 'details': r[4] or ''} for r in cur.fetchall()]
        con.close()
        return rows
    except Exception:  # noqa: BLE001
        return []


def log_action(db_path, user, action, detail=''):
    try:
        con = sqlite3.connect(db_path, timeout=5)
        con.execute(
            'CREATE TABLE IF NOT EXISTS audit ('
            ' ts TEXT, email TEXT, role TEXT, action TEXT, detail TEXT)')
        con.execute(
            'INSERT INTO audit VALUES (datetime("now","localtime"), ?, ?, ?, ?)',
            ((user or {}).get('email', '-'), (user or {}).get('role', '-'),
             action, detail))
        con.commit()
        con.close()
    except Exception:  # noqa: BLE001
        pass


# ─── Authentifizierung / Session ────────────────────────────────────────────
def authenticate(email, password):
    """Prueft E-Mail/Passwort. Gespeichertes Passwort hat Vorrang vor Env."""
    email = (email or "").strip().lower()
    if not password:
        return None
    role = next((r for r, e in role_emails().items() if e == email), None)
    if not role:
        return None
    stored = _check_stored(role, password)
    if stored is True:
        return {"email": email, "role": role}
    if stored is False:
        return None
    env_pw = _env_pass(role)
    if env_pw and hmac.compare_digest(env_pw, password):
        return {"email": email, "role": role}
    return None


def _sign(payload):
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def create_token(email, role, exp=None):
    exp = int(exp) if exp else int(time.time()) + SESSION_HOURS * 3600
    payload = email + "|" + role + "|" + str(exp)
    return payload + "|" + _sign(payload)


def verify_token(token):
    try:
        email, role, exp, sig = token.rsplit("|", 3)
    except (ValueError, AttributeError):
        return None
    if not hmac.compare_digest(_sign(email + "|" + role + "|" + exp), sig):
        return None
    if int(exp) < int(time.time()):
        return None
    return {"email": email, "role": role}


def get_current_user(request):
    token = request.cookies.get(COOKIE_NAME)
    return verify_token(token) if token else None


# ─── Cookie-/Domain-Helfer ──────────────────────────────────────────────────
def _host(request):
    return (request.url.hostname or "").lower()


def _on_shared_domain(request):
    """Laeuft der Request unter der gemeinsamen SSO-Domain?"""
    if not _DOMAIN_ROOT:
        return False
    h = _host(request)
    return h == _DOMAIN_ROOT or h.endswith("." + _DOMAIN_ROOT)


def _cookie_domain_for(request):
    # Nur die gemeinsame Domain setzen, wenn der Request auch dort laeuft -
    # sonst (z. B. *.sliplane.app) host-eigener Cookie, damit nichts bricht.
    return COOKIE_DOMAIN if _on_shared_domain(request) else None


def _set_session_cookie(resp, request, token):
    resp.set_cookie(
        COOKIE_NAME, token, httponly=True, max_age=SESSION_HOURS * 3600,
        samesite="lax", secure=(request.url.scheme == "https"),
        domain=_cookie_domain_for(request),
    )


def _clear_session_cookie(resp, request):
    resp.delete_cookie(COOKIE_NAME, domain=_cookie_domain_for(request))


def _safe_next(next_url):
    """Nur relative Pfade oder URLs unterhalb der gemeinsamen Domain zulassen
    (verhindert Open-Redirects)."""
    if not next_url:
        return None
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    try:
        p = urlparse(next_url)
    except ValueError:
        return None
    if p.scheme in ("http", "https") and p.hostname:
        h = p.hostname.lower()
        if _DOMAIN_ROOT and (h == _DOMAIN_ROOT or h.endswith("." + _DOMAIN_ROOT)):
            return next_url
        if h in _sso_hosts():
            return next_url
    return None


def _after_login(nxt):
    """Ziel nach der Anmeldung: relative Pfade direkt, Werkzeuge per Ticket."""
    if not nxt:
        return "/"
    if nxt.startswith("/"):
        return nxt
    return ("/go?to=" + quote(nxt, safe="")) if IS_PORTAL else "/"


# ─── Middleware: bedient die Anmeldung selbst ───────────────────────────────
async def _serve(request, call_next):
    """Route ausfuehren und - falls die HTML-Antwort eine Navigationsleiste
    (<nav class="switch">) enthaelt - diese zentral und rollenabhaengig
    ersetzen. So gibt es EINE Quelle für die obere Navigation; die Module
    liefern nur den Platzhalter-Block. Nicht-HTML (Downloads, JSON) bleibt
    unangetastet."""
    response = await call_next(request)
    # Nur einfache, unkomprimierte HTML-Antworten mit Statuscode 200 anfassen.
    # Downloads (ZIP/PDF/JSON), Redirects, Fehler, komprimierte oder gestreamte
    # Antworten bleiben voellig unveraendert.
    if response.status_code != 200:
        return response
    ctype = response.headers.get("content-type", "")
    if "text/html" not in ctype.lower():
        return response
    if response.headers.get("content-encoding"):
        return response
    if not hasattr(response, "body_iterator"):
        return response
    body = b""
    async for chunk in response.body_iterator:
        body += chunk if isinstance(chunk, (bytes, bytearray)) else chunk.encode("utf-8")
    try:
        text = body.decode("utf-8", "replace")
        if 'class="switch"' in text:
            user = getattr(request.state, "user", None) or get_current_user(request)
            nav = NAV_STYLE + nav_html(_active_nav_key(request), user)
            text = _NAV_RE.sub(lambda _m: nav, text, count=1)
            body = text.encode("utf-8")
    except Exception:  # noqa: BLE001 - im Zweifel Originalinhalt unveraendert ausliefern
        pass
    skip = {"content-length", "content-type"}
    headers = {k: v for k, v in response.headers.items() if k.lower() not in skip}
    return Response(content=body, status_code=response.status_code,
                    headers=headers, media_type=(ctype or "text/html; charset=utf-8"))


async def auth_middleware(request, call_next):
    path = request.url.path
    # Angemeldeten Nutzer für nachgelagerte Routen bereitstellen. Manche app.py
    # lesen den Nutzer ueber request.state.user (statt get_current_user) - deshalb
    # hier immer setzen, sonst sehen diese Routen faelschlich "nicht angemeldet".
    request.state.user = get_current_user(request)
    if path in PUBLIC_PATHS or path.startswith("/static"):
        return await call_next(request)

    if path == "/logout":
        return _do_logout(request)

    if IS_PORTAL:
        if path == "/go":
            return _go_handler(request)
        if path == "/login":
            return await _login_handler(request)
        if path == "/setup":
            return await _setup_handler(request)
        if path == "/konto":
            return await _konto_handler(request)
        if get_current_user(request):
            return await _serve(request, call_next)
        return RedirectResponse("/login?next=" + quote(str(request.url)), status_code=303)

    # ── Modul-Modus ──
    if path == "/sso":
        return _sso_handler(request)
    if path in ("/setup", "/konto"):
        # Passwort-Verwaltung gibt es nur zentral im Portal.
        return RedirectResponse((PORTAL_URL + path) if PORTAL_URL else "/", status_code=303)
    if get_current_user(request):
        return await _serve(request, call_next)
    # Lokaler Login nur noch als Rückfallebene (POST oder /login?lokal=1).
    if path == "/login" and (request.method == "POST" or request.query_params.get("lokal")
                             or not PORTAL_URL):
        return await _login_handler(request)
    if PORTAL_URL:
        if path == "/login":
            return _to_portal_login(request, _rel(request.query_params.get("next")) or "/")
        return _to_portal_login(request)
    return RedirectResponse("/login", status_code=303)


def _do_logout(request):
    target = "/login"
    if not IS_PORTAL and PORTAL_URL:
        target = PORTAL_URL + "/logout"
    resp = RedirectResponse(target, status_code=303)
    _clear_session_cookie(resp, request)
    return resp


async def _login_handler(request):
    if request.method == "POST":
        form = await request.form()
        user = authenticate(form.get("email", ""), form.get("password", ""))
        if not user:
            return HTMLResponse(
                login_page_html(APP_NAME, error="E-Mail oder Passwort ist falsch.",
                                next_url=_safe_next(form.get("next"))),
                status_code=401)
        token = create_token(user["email"], user["role"])
        target = _after_login(_safe_next(form.get("next")))
        resp = RedirectResponse(target, status_code=303)
        _set_session_cookie(resp, request, token)
        return resp
    nxt = _safe_next(request.query_params.get("next"))
    if get_current_user(request):
        return RedirectResponse(_after_login(nxt), status_code=303)
    return HTMLResponse(login_page_html(APP_NAME, next_url=nxt))


async def _setup_handler(request):
    if not needs_setup():
        return RedirectResponse("/login", status_code=303)
    if request.method == "POST":
        form = await request.form()
        token = form.get("token", "")
        if not check_setup_token(token):
            return HTMLResponse(
                setup_page_html(APP_NAME, token, error="Setup-Link ungültig oder abgelaufen."),
                status_code=403)
        try:
            set_password("admin", form.get("admin_pw", ""))
            set_password("retail", form.get("retail_pw", ""))
        except ValueError as e:
            return HTMLResponse(setup_page_html(APP_NAME, token, error=str(e)), status_code=400)
        return RedirectResponse("/login", status_code=303)
    t = request.query_params.get("t", "")
    if not check_setup_token(t):
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'>"
            "<p style='font:15px system-ui;max-width:420px;margin:60px auto;padding:0 18px'>"
            "Setup-Link ungültig. Bitte den vollständigen Link mit Token aus den Server-Logs "
            "verwenden.</p>", status_code=403)
    return HTMLResponse(setup_page_html(APP_NAME, t))


async def _konto_handler(request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login?next=/konto", status_code=303)
    if user.get("role") != "admin":
        return RedirectResponse("/", status_code=303)
    if request.method == "POST":
        form = await request.form()
        apw = (form.get("admin_pw", "") or "").strip()
        rpw = (form.get("retail_pw", "") or "").strip()
        changed = []
        try:
            if apw:
                set_password("admin", apw)
                changed.append("Admin")
            if rpw:
                set_password("retail", rpw)
                changed.append("Retail")
        except ValueError as e:
            return HTMLResponse(konto_page_html(APP_NAME, user, error=str(e)), status_code=400)
        if not changed:
            return HTMLResponse(konto_page_html(
                APP_NAME, user, error="Kein Passwort geändert - beide Felder waren leer."))
        return HTMLResponse(konto_page_html(
            APP_NAME, user, message="Passwort geändert für: " + " und ".join(changed) + "."))
    return HTMLResponse(konto_page_html(APP_NAME, user))


def _active_nav_key(request):
    """Aktiven Nav-Eintrag aus dem Host ableiten. Funktioniert auf
    *.sliplane.app UND spaeter auf *.werkbank.skyport-group.de."""
    if IS_PORTAL:
        return "portal"
    h = _host(request)
    for key, needles in (
        ("stammdaten", ("stammdaten", "haendler")),
        ("deltav", ("deltav", "delta-v")),
        ("rechner", ("containerpreisrechner", "containerpreis")),
        ("schweiz", ("schweiz-export", "schweiz")),
        ("sortiment", ("sortiment",)),
        ("wayfair", ("wayfair",)),
        ("avis", ("avis-konverter", "avis")),
        ("viking", ("viking",)),
        ("cb", ("cb-web", "cb.")),
        ("hfn", ("hfn",)),
    ):
        if any(n in h for n in needles):
            return key
    return ""


def nav_html(active_key="", user=None):
    """Rendert die obere Werkzeug-Navigation rollenabhaengig. admin_only-
    Eintraege (Haendler-Stammdaten) erscheinen nur für Rolle 'admin'."""
    role = (user or {}).get("role", "")
    links = []
    for key, label, url, admin_only in NAV_TOOLS:
        if admin_only and role != "admin":
            continue
        if key == active_key:
            continue  # aktuelles Modul nicht in der Leiste auflisten
        if key == "portal":
            href = "/" if IS_PORTAL else (PORTAL_URL or url)
        else:
            href = portal_link(url)
        links.append('<a href="' + href + '">' + label + '</a>')
    return '<nav class="switch">' + "".join(links) + '</nav>'


def user_header_html(user):
    """Kompakter Nutzerhinweis für die Kopfzeile.

    Die Links (Passwörter / Abmelden) bekommen per Inline-Style eine weisse,
    gut lesbare Schrift - der dunkle Kopf faerbte sie sonst im Browser-Standard-
    Blau (#0000EE), das auf Dunkel kaum lesbar ist. Inline + !important schlaegt
    lokales Modul-CSS, damit es in JEDEM Modul weiss ist."""
    if not user:
        return ""
    a = '<a style="color:#3730a3;text-decoration:none;font-weight:500" href='
    extra = ""
    if IS_PORTAL and user.get("role") == "admin":
        extra = ' &middot; ' + a + '"/konto">Passwörter</a>'
    return (escape(user["email"]) + ' (' + escape(user["role"]) + ')'
            + extra + ' &middot; ' + a + '"/logout">Abmelden</a>')


# ─── Seiten (gemeinsames Layout) ────────────────────────────────────────────
def _shell(app_name, inner_html):
    return """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>""" + escape(app_name) + """</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{--accent:#4f46e5;--accent-hover:#4338ca;--ink:#151a21;--mut:#58616e;--line:#e7ecf2;--line2:#d5dde5;--surface:#fff;--ground:#f1f5f9}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Inter",-apple-system,"Segoe UI",Roboto,sans-serif;font-size:15px;line-height:1.55;background:var(--ground);color:var(--ink);-webkit-font-smoothing:antialiased}
  header{background:var(--surface);color:var(--ink);padding:0 22px;height:60px;display:flex;align-items:center;border-bottom:1px solid var(--line);font-weight:600;font-size:15px}
  .accentline{height:3px;background:var(--accent)}
  main{max-width:440px;margin:56px auto;padding:0 18px}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:30px;box-shadow:0 1px 2px rgba(20,26,33,.05),0 1px 1px rgba(20,26,33,.04)}
  h1{font-size:22px;font-weight:700;letter-spacing:-.01em;margin:0 0 4px}
  .sub{color:var(--mut);margin:0 0 22px;font-size:14px}
  label{display:block;font-size:13px;font-weight:600;margin:0 0 5px;color:var(--mut)}
  input{width:100%;padding:11px 12px;border:1px solid var(--line2);border-radius:6px;font-size:15px;margin-bottom:16px;font-family:inherit;background:var(--surface);color:var(--ink)}
  input:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
  .hint{font-size:12px;color:var(--mut);margin:-10px 0 16px}
  button{width:100%;padding:12px;border:1px solid transparent;border-radius:6px;background:var(--accent);color:#fff;font-size:15px;font-weight:500;cursor:pointer;font-family:inherit;transition:.12s}
  button:hover{background:var(--accent-hover)}
  .sec{border-top:1px solid var(--line);margin:22px 0 18px}
  .msg{border-radius:10px;padding:10px 12px;font-size:14px;margin-bottom:18px}
  .err{background:#fdeceb;color:#c0362c;border:1px solid #f4c9c5}
  .ok{background:#e6f6ec;color:#087443;border:1px solid #bce6cd}
  a.back{display:inline-block;margin-top:16px;color:var(--accent);font-size:14px;text-decoration:none}
  a.back:hover{text-decoration:underline}
</style>
</head>
<body>
<header><b>Skyport <span style="color:var(--accent)">&middot;</span> Werkbank</b></header>
<div class="accentline"></div>
<main><div class="card">""" + inner_html + """</div></main>
</body>
</html>"""


def login_page_html(app_name="Werkbank", error=None, next_url=None):
    err = ('<div class="msg err">' + escape(error) + '</div>') if error else ""
    hidden = ('<input type="hidden" name="next" value="' + escape(next_url) + '">') if next_url else ""
    inner = ("<h1>" + escape(app_name) + "</h1>"
             '<p class="sub">Bitte mit den Werkbank-Zugangsdaten anmelden.</p>'
             + err +
             '<form method="post" action="/login">'
             + hidden +
             '<label for="email">E-Mail</label>'
             '<input id="email" name="email" type="email" autocomplete="username" autofocus required>'
             '<label for="password">Passwort</label>'
             '<input id="password" name="password" type="password" autocomplete="current-password" required>'
             '<button type="submit">Anmelden</button>'
             '</form>')
    return _shell("Anmelden · " + app_name, inner)


def setup_page_html(app_name, token, error=None):
    err = ('<div class="msg err">' + escape(error) + '</div>') if error else ""
    emails = role_emails()
    admin_e = escape(emails.get("admin", "admin"))
    retail_e = escape(emails.get("retail", "retail"))
    inner = ("<h1>Erst-Einrichtung</h1>"
             '<p class="sub">Lege jetzt die Passwörter für die beiden Konten fest. '
             'Sie werden nur verschluesselt (gehasht) gespeichert.</p>'
             + err +
             '<form method="post" action="/setup">'
             '<input type="hidden" name="token" value="' + escape(token) + '">'
             '<label>Passwort für Admin (' + admin_e + ')</label>'
             '<input name="admin_pw" type="password" autocomplete="new-password" required>'
             '<div class="hint">Mindestens ' + str(MIN_PW_LEN) + ' Zeichen.</div>'
             '<label>Passwort für Retail (' + retail_e + ')</label>'
             '<input name="retail_pw" type="password" autocomplete="new-password" required>'
             '<button type="submit">Passwörter setzen</button>'
             '</form>')
    return _shell("Erst-Einrichtung · " + app_name, inner)


def konto_page_html(app_name, user, message=None, error=None):
    emails = role_emails()
    admin_e = escape(emails.get("admin", "admin"))
    retail_e = escape(emails.get("retail", "retail"))
    msg = ('<div class="msg ok">' + escape(message) + '</div>') if message else ""
    err = ('<div class="msg err">' + escape(error) + '</div>') if error else ""
    inner = ("<h1>Passwort-Verwaltung</h1>"
             '<p class="sub">Nur für Admins. Gilt für alle Module. '
             'Feld leer lassen = unveraendert. Mindestens ' + str(MIN_PW_LEN) + ' Zeichen.</p>'
             + msg + err +
             '<form method="post" action="/konto">'
             '<label>Neues Passwort für Admin (' + admin_e + ')</label>'
             '<input name="admin_pw" type="password" autocomplete="new-password">'
             '<div class="sec"></div>'
             '<label>Neues Passwort für Retail (' + retail_e + ')</label>'
             '<input name="retail_pw" type="password" autocomplete="new-password">'
             '<button type="submit">Aenderungen speichern</button>'
             '</form>'
             '<a class="back" href="/">&larr; zurück</a>')
    return _shell("Passwörter · " + app_name, inner)

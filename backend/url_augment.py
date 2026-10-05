"""
url_augment.py — PhishGuard AI
==============================
Shared helpers for breaking the "URL has a path => phishing" dataset artifact.

The old pipeline taught the model a shortcut: legitimate examples were mostly
bare domains (Tranco) while phishing examples carried full paths. This module
provides a diverse path vocabulary and functions to:
  • add a realistic, varied path to a bare URL   (add_path)
  • strip a URL down to scheme://host            (strip_to_host)
  • test whether a URL carries a path             (has_path)
  • extract the registrable domain               (registrable_domain)

Used by train_ml_strong.py (train-time decorrelation) and
build_legit_dataset.py (diverse legit URLs on rebuild).
"""

import random
from urllib.parse import urlparse

# A wide, varied path pool: ordinary browsing paths AND security-flavoured ones.
# Security-flavoured paths are LEGITIMATE when they sit on a legit domain
# (real banks/services have /login, /secure/checkout, /reset-password), so
# including them on legit domains teaches the model that the PATH is not the
# phishing signal — the HOST is.
PATH_POOL = [
    "", "/", "/home", "/index.html", "/about", "/about-us", "/contact",
    "/contact-us", "/pricing", "/plans", "/features", "/faq", "/help",
    "/help/faq", "/support", "/support/tickets/2481", "/careers",
    "/careers/apply?job=1042", "/team", "/blog", "/blog/2024/03/getting-started",
    "/news", "/news/latest", "/press", "/products", "/products/item/1042",
    "/category/electronics/phones", "/shop/deals", "/cart", "/checkout",
    "/orders/558213", "/search?q=running+shoes", "/results?page=3",
    "/gallery", "/gallery/photos/2023", "/events/summit-2024", "/downloads",
    "/download/report.pdf", "/docs", "/docs/getting-started", "/api/v1/status",
    "/dashboard", "/dashboard/overview", "/user/profile", "/u/12345",
    "/settings", "/settings/preferences", "/notifications",
    # security-flavoured (legit on a legit host)
    "/login", "/signin", "/account", "/account/settings", "/my-account",
    "/secure/checkout", "/verify-email", "/reset-password", "/forgot-password",
    "/billing", "/billing/invoices", "/security", "/security/2fa",
    "/update-profile", "/confirm?token=a1b2c3", "/auth/callback",
    "/wp-login.php", "/wp-admin", "/portal", "/portal/access",
]

_TWO_PART_TLDS = {"co", "ac", "gov", "net", "org", "edu", "com"}

# Segments used to build DEEP, multi-level paths (2–6 deep), often stacking
# security-flavoured words. Applied to BOTH classes at train time so that path
# DEPTH and keyword-STACKING — not just path presence — are decorrelated from
# the label. Without this, legit hosts only ever saw shallow paths in training,
# so a deep stacked path like /a/b/login/verify/account tipped a legit domain
# (e.g. byjus.com) toward phishing. The HOST must decide, not the path shape.
DEEP_SEGMENTS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "billing", "auth", "session", "user", "profile", "reset", "password",
    "token", "callback", "home", "app", "dashboard", "portal", "settings",
    "orders", "checkout", "products", "category", "search", "help", "support",
    "en", "in", "us", "v1", "v2", "id", "page", "view", "list", "detail",
]



def _prep(url: str) -> str:
    """Normalize before urlparse: drop defang brackets that crash the parser
    (e.g. `evil[.]com`, `hxxp://a[.]b`) — matches features.py's bracket strip."""
    return str(url).replace("[", "").replace("]", "")


def _host_of(url: str) -> str:
    try:
        u = _prep(url)
        parsed = urlparse(u if u.startswith("http") else "http://" + u)
        host = parsed.netloc or parsed.path.split("/")[0]
        host = host.split("@")[-1].split(":")[0]
        return host.lower()
    except Exception:
        return ""


def registrable_domain(url: str) -> str:
    """Best-effort registrable domain, matching predict_ml_only's rule."""
    host = _host_of(url)
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) > 1 else host


def has_path(url: str) -> bool:
    try:
        u = _prep(url)
        p = urlparse(u if u.startswith("http") else "http://" + u)
        return len(p.path.strip("/")) > 0 or bool(p.query)
    except Exception:
        return False


def strip_to_host(url: str) -> str:
    """Return scheme://host with no path/query (bare domain URL)."""
    try:
        u = _prep(url)
        parsed = urlparse(u if u.startswith("http") else "http://" + u)
        scheme = parsed.scheme or "http"
        host = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{host}"
    except Exception:
        return ""


def add_path(url: str, rng: random.Random | None = None) -> str:
    """Return the URL with a random realistic path appended to its host.

    ~35% of the time builds a DEEP (2–7 segment) path, often stacking
    security-flavoured words (see DEEP_SEGMENTS). Because this is applied to
    both classes during train-time augmentation, deep/stacked paths carry no
    class signal — only the host does.

    Rate raised 0.15 → 0.35 and max depth 6 → 7 (v3.4): at 0.15 a non-allowlisted
    legit host only rarely saw a deep keyword-stacked path in training, while the
    numeric features that count path depth / keyword-stacking are ×15 weighted —
    so the model extrapolated and a pathological path like
    /login/verify/account/secure/update/confirm/billing tipped a legit host
    (e.g. vedantu.com, not on the allowlist) from SAFE over the line. Showing
    BOTH classes deep keyword-stacks far more often anchors the verdict on the
    HOST. Symmetric across classes, so path shape stays decorrelated from label;
    the net effect on FP/recall is gated by fp_sweep.py / fresh_recall_probe.py /
    parent_path_probe.py before shipping."""
    rng = rng or random
    base = strip_to_host(url).rstrip("/")
    if rng.random() < 0.35:
        depth = rng.randint(2, 7)
        segs = [rng.choice(DEEP_SEGMENTS) for _ in range(depth)]
        return base + "/" + "/".join(segs)
    path = rng.choice(PATH_POOL)
    if not path:
        # occasionally add a shallow two-segment path for variety
        path = "/" + rng.choice(["home", "app", "portal", "en", "in"])
    return base + path


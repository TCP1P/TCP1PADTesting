"""
HEALTH checks for the koth-throne hill — KotH has NO per-team flag, so this is
a pure health probe (Ok / Mumble / Offline). It gates whether the current king
earns hold points (Ok) or eats the broken-hill penalty. Do NOT reference
t.flag (empty for KotH), and do NOT crown (never write /koth/king) — only read
and assert the hill is alive and the crown machinery still works.

Verdicts: return = Ok, raise Mumble = up-but-degraded, t.get/post raise Offline.
"""
from checker import Mumble, check


@check
def hill_is_up(t):
    """GET / must answer 200 — otherwise the hill is down for everyone."""
    r = t.get("/")
    if r.status_code != 200:
        raise Mumble(f"GET / returned {r.status_code}")


@check
def throne_view_alive(t):
    """The throne view (which surfaces the current king) must keep rendering."""
    body = t.get("/").text
    if "king of the hill" not in body or "current king token" not in body:
        raise Mumble(f"unexpected throne response: {body[:120]!r}")


@check
def crown_is_guarded(t):
    """The crown endpoint must still be reachable AND still reject a
    non-admin (so the hill is claimable by exploit, not by everyone, and a
    defender hasn't bricked the path entirely). A non-admin POST /throne
    should be a clean 4xx — not 5xx (broken) and not 200 (would let anyone
    crown for free)."""
    r = t.post("/throne", json={"token": "healthprobe"})
    if r.status_code >= 500:
        raise Mumble(f"/throne 5xx (crown machinery broken): {r.status_code}")
    if r.status_code == 200:
        raise Mumble("/throne accepted an unauthenticated crown (hill not contestable)")

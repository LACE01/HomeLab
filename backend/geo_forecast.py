"""Item 51 (PYTHIA, AI-forecasting half) — walled off ON PURPOSE.

PYTHIA is an open-source live-globe + AI-forecasting tool. The globe / situational-
awareness half is folded into world_monitor.py (real observed events, geolocated).
This module is the OTHER half, and it is deliberately NOT a working forecasting
feature. Here is why, encoded as behaviour rather than a comment someone can skip:

  * Reliable geopolitical forecasting is an unsolved problem. In a government
    platform there is a real risk that staff read "PYTHIA predicts X" as an
    intelligence product rather than what it is -- an algorithmic guess.
  * So this ships INERT: no forecasting model and no external feed are wired in.
    A vetted source must be deliberately registered by an operator before this
    can emit anything, exactly like the active-validation module ships with no
    executor.
  * It is OFF by default (a feature flag that fails CLOSED), it is decision_bearing
    = False in every payload, every payload carries a plain-language disclaimer,
    and it is kept on its own surface. It must NEVER be rendered next to real
    KEV / findings data -- the routes and the UI enforce that separation.

The point of the module existing at all is to be the governed boundary: a clearly
labelled, off-by-default, non-authoritative experiment, so that if forecasting is
ever explored it happens here, under these guardrails, and not smuggled in beside
data operators act on.
"""

FEATURE_FLAG = "experimental_geo_forecast"

DISCLAIMER = (
    "EXPERIMENTAL — NOT AN INTELLIGENCE PRODUCT. Any output here is an algorithmic "
    "guess, not a verified assessment. Geopolitical forecasting is unsolved; do not "
    "use this to make security, operational, or policy decisions, and do not present "
    "it alongside KEV, findings, or other observed data."
)

# A vetted forecast source is a callable an operator explicitly registers AFTER
# clearing its feeds through legal/policy review. Until then it is None and this
# module produces no forecasts at all -- it cannot, by construction.
_FORECAST_SOURCE = None


def register_forecast_source(fn):
    """Register (or clear, with None) a vetted forecast source. Intentionally the
    only way to make this module emit anything -- and calling it is an explicit,
    auditable act, not something any feed can trigger on its own."""
    global _FORECAST_SOURCE
    _FORECAST_SOURCE = fn


def has_source() -> bool:
    return _FORECAST_SOURCE is not None


async def feature_enabled(db) -> bool:
    """Fail CLOSED: only a real boolean True on the flag enables this. Absence, a
    missing field, or a non-boolean value all read as OFF -- unlike the ordinary
    fail-open flag check, because this is the more dangerous default to get wrong."""
    doc = await db.feature_flags.find_one({"key": FEATURE_FLAG}, {"_id": 0, "enabled": 1})
    return bool(doc and doc.get("enabled") is True)


async def status(db) -> dict:
    """Always-safe status: what this is, that it's off/experimental, and whether a
    vetted source has been registered. Never returns a forecast."""
    return {
        "feature": FEATURE_FLAG,
        "enabled": await feature_enabled(db),
        "experimental": True,
        "decision_bearing": False,
        "vetted_source_registered": has_source(),
        "disclaimer": DISCLAIMER,
        "separation_policy": ("Forecasts must never be shown next to KEV, findings, "
                               "or other observed data. This lives on its own surface."),
    }


async def forecasts(db) -> dict:
    """Return experimental forecasts IF (and only if) the feature is enabled AND a
    vetted source has been registered. With no source registered -- the shipped
    state -- it returns an empty set with the disclaimer, never a fabricated guess.
    Every payload is stamped experimental + non-decision-bearing."""
    enabled = await feature_enabled(db)
    base = {
        "experimental": True,
        "decision_bearing": False,
        "disclaimer": DISCLAIMER,
        "enabled": enabled,
        "vetted_source_registered": has_source(),
        "items": [],
    }
    if not enabled:
        base["message"] = "The experimental forecast feature is disabled."
        return base
    if not has_source():
        base["message"] = ("No vetted forecast source is configured. This module ships with "
                            "none by design -- its feeds must be cleared through legal/policy "
                            "review and registered explicitly before it can emit anything.")
        return base
    try:
        raw = await _FORECAST_SOURCE(db)
    except Exception as e:
        base["message"] = f"The registered forecast source errored: {e}"
        return base
    items = []
    for r in (raw or []):
        # Re-stamp every item so a source can't strip the guardrails.
        items.append({**r, "experimental": True, "decision_bearing": False,
                      "confidence_is_estimated": True})
    base["items"] = items
    base["message"] = f"{len(items)} experimental forecast(s) from the registered source."
    return base

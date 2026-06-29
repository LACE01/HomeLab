"""Tests for VulnOps Report Builder (Iteration 2): pre-built catalog + dynamic builder."""
import os
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
API = f"{BASE}/api"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{API}/auth/login",
                      json={"email": "admin@vulnops.io", "password": "admin123"},
                      timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture(scope="session")
def H(token):
    return {"Authorization": f"Bearer {token}"}


# --- Catalog -----------------------------------------------------------
def test_catalog(H):
    r = requests.get(f"{API}/v1/reports/catalog", headers=H, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert len(d["items"]) == 10
    assert len(d["group_fields"]) == 9
    assert len(d["filter_fields"]) == 7
    assert len(d["metrics"]) == 2
    assert len(d["date_fields"]) == 4


# --- Pre-built reports ------------------------------------------------
PREBUILT = ["open_by_severity", "sla_compliance_trend", "top_risk_assets",
            "aging_report", "throughput", "critical_by_bu", "kev_exposure",
            "open_exceptions", "reopened", "overdue_critical"]


@pytest.mark.parametrize("rid", PREBUILT)
def test_prebuilt_csv(H, rid):
    r = requests.get(f"{API}/v1/reports/run/{rid}?fmt=csv", headers=H, timeout=30)
    assert r.status_code == 200, f"{rid} csv {r.status_code} {r.text[:200]}"
    assert "text/csv" in r.headers.get("content-type", "")
    assert len(r.content) > 0


@pytest.mark.parametrize("rid", PREBUILT)
def test_prebuilt_pdf(H, rid):
    r = requests.get(f"{API}/v1/reports/run/{rid}?fmt=pdf", headers=H, timeout=30)
    assert r.status_code == 200, f"{rid} pdf {r.status_code} {r.text[:200]}"
    assert "application/pdf" in r.headers.get("content-type", "")
    assert r.content[:4] == b"%PDF"


def test_open_by_severity_columns(H):
    r = requests.get(f"{API}/v1/reports/run/open_by_severity?fmt=csv", headers=H, timeout=15)
    text = r.text
    assert "severity" in text and "count" in text
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        assert sev in text, f"missing {sev}"


def test_top_risk_assets_columns(H):
    r = requests.get(f"{API}/v1/reports/run/top_risk_assets?fmt=csv", headers=H, timeout=15)
    header = r.text.splitlines()[0]
    for col in ["hostname", "open_findings", "critical", "risk_score_sum"]:
        assert col in header


def test_throughput_30_rows(H):
    r = requests.get(f"{API}/v1/reports/run/throughput?fmt=csv", headers=H, timeout=15)
    lines = [l for l in r.text.splitlines() if l.strip()]
    # 1 header + 30 rows
    assert len(lines) == 31, f"expected 31 lines, got {len(lines)}"


def test_invalid_report_404(H):
    r = requests.get(f"{API}/v1/reports/run/does_not_exist?fmt=pdf", headers=H, timeout=15)
    assert r.status_code == 404


def test_invalid_fmt_400(H):
    r = requests.get(f"{API}/v1/reports/run/open_by_severity?fmt=xls", headers=H, timeout=15)
    assert r.status_code == 400


# --- Custom builder ---------------------------------------------------
def test_custom_csv_basic(H):
    body = {"fmt": "csv", "group_by": "owner_team", "metric": "risk_sum",
            "filters": {"severity": ["Critical", "High"]}}
    r = requests.post(f"{API}/v1/reports/run-custom", json=body, headers=H, timeout=20)
    assert r.status_code == 200, r.text[:200]
    assert "text/csv" in r.headers.get("content-type", "")
    header = r.text.splitlines()[0]
    for col in ["owner_team", "count", "critical", "risk_sum"]:
        assert col in header, f"missing {col} in {header}"


def test_custom_bad_group_by_400(H):
    body = {"fmt": "csv", "group_by": "invalid_field", "metric": "count", "filters": {}}
    r = requests.post(f"{API}/v1/reports/run-custom", json=body, headers=H, timeout=15)
    assert r.status_code == 400


def test_custom_pdf(H):
    body = {"fmt": "pdf", "group_by": "severity", "metric": "count", "filters": {}}
    r = requests.post(f"{API}/v1/reports/run-custom", json=body, headers=H, timeout=20)
    assert r.status_code == 200
    assert "application/pdf" in r.headers.get("content-type", "")
    assert r.content[:4] == b"%PDF"


def test_custom_kev_filter(H):
    body = {"fmt": "csv", "group_by": "severity", "metric": "count",
            "filters": {"kev_flag": True}}
    r = requests.post(f"{API}/v1/reports/run-custom", json=body, headers=H, timeout=15)
    assert r.status_code == 200
    # The result should be valid CSV
    assert "severity" in r.text.splitlines()[0]


def test_custom_date_filter_narrows(H):
    body_all = {"fmt": "csv", "group_by": "severity", "metric": "count", "filters": {}}
    r_all = requests.post(f"{API}/v1/reports/run-custom", json=body_all, headers=H, timeout=15)

    body_narrow = {"fmt": "csv", "group_by": "severity", "metric": "count", "filters": {},
                   "date_field": "first_seen_at",
                   "date_from": "2099-01-01T00:00:00+00:00",
                   "date_to": "2099-12-31T00:00:00+00:00"}
    r_n = requests.post(f"{API}/v1/reports/run-custom", json=body_narrow, headers=H, timeout=15)
    assert r_n.status_code == 200
    # narrow should have fewer or equal lines (likely just header)
    assert len(r_n.text.splitlines()) <= len(r_all.text.splitlines())


# --- Regression: original report endpoints still work ----------------
def test_legacy_csv_findings(H):
    r = requests.get(f"{API}/v1/reports/csv/findings", headers=H, timeout=15)
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")


def test_legacy_pdf_executive(H):
    r = requests.get(f"{API}/v1/reports/pdf/executive", headers=H, timeout=30)
    assert r.status_code == 200
    assert "application/pdf" in r.headers.get("content-type", "")

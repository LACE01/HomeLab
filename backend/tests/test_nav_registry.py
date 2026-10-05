"""Item 40 -- the sidebar renders from lib/navRegistry.js, so the registry must
cover every navigable page in App.js, stay at <=12 top-level sections, two
levels deep, and list each route once."""
import os, re
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "frontend", "src")
reg = open(os.path.join(ROOT, "lib", "navRegistry.js")).read()
app = open(os.path.join(ROOT, "App.js")).read()
side = open(os.path.join(ROOT, "components", "Sidebar.jsx")).read()

sections = re.findall(r'\{ key: "([^"]+)", label: "([^"]+)", icon: \w+, items: \[', reg)
assert 8 <= len(sections) <= 12, len(sections)
tos = re.findall(r'\{ label: "[^"]+", to: "([^"]+)", icon: \w+, testid: "[^"]+"', reg)
assert len(tos) == len(set(tos)), "a route is listed in two sections"
routes = {r for r in re.findall(r'path="([^"]+)"', app) if ":" not in r}
NOT_NAV = {"/login", "/auth/callback", "/change-password", "/enroll-mfa", "/security", "/exceptions/new"}
missing = routes - set(tos) - NOT_NAV
assert not missing, f"pages with no way to reach them from the nav: {sorted(missing)}"
assert "to=\"/" not in side.split("<nav")[1].split("</nav>")[0], "sidebar must render from the registry, not hard-coded links"
print(f"PASS: {len(tos)} pages in {len(sections)} sections; every App route reachable; sidebar derives from registry")

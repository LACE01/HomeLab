"""Report layout templates -- the report is configuration, not code.

Every time someone wanted a section moved, renamed, or dropped, that was a code
change and a deploy. This makes the layout a versioned DB record instead: an
ordered list of blocks, each with a title you choose, a visibility flag, and
per-block options (e.g. how many findings to show, whether to draw the matrix).

The renderers -- the in-app print view, the shared/external report, and the Word
export -- all read the SAME template, so a layout change lands everywhere at once
and the three can't drift apart.

Two deliberate guarantees:

  * INTERNAL-ONLY blocks (working notes, raw evidence) carry an `internal_only`
    flag. The shared/external renderer drops them no matter what the template
    says -- a layout choice must never be able to leak internal notes to a
    vendor.
  * Templates are VERSIONED and a report records which version it was rendered
    under, the same way playbooks and questionnaires already do, so a report
    produced last quarter can still be explained.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

# Every block the renderers know how to draw. A template can reorder, retitle,
# hide, or configure these, but not invent one -- an unknown block would just be
# a silently blank section.
BLOCK_CATALOG = [
    {"type": "header", "name": "Report header",
     "description": "Review number, date, reviewer, requestor.",
     "default_title": "Security Review Report", "internal_only": False, "removable": False,
     "options": {}},
    {"type": "what_reviewed", "name": "What was reviewed",
     "description": "One line naming the product/vendor and intended use.",
     "default_title": "What was reviewed", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "risk_verdict", "name": "Risk verdict badges",
     "description": "Inherent → residual risk badges, the headline of the whole report.",
     "default_title": "Risk verdict", "internal_only": False, "removable": True,
     "options": {"show_not_adopting": True}},
    {"type": "confidence", "name": "Assessment confidence",
     "description": "Confidence percentage and how many questions were unknown or pending.",
     "default_title": "Assessment confidence", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "compensating_controls", "name": "Compensating controls",
     "description": "The controls that move inherent risk down to residual.",
     "default_title": "Compensating controls", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "risk_matrix", "name": "5×5 risk matrix",
     "description": "Likelihood × impact grid with the inherent/residual/not-adopting positions.",
     "default_title": "Risk matrix", "internal_only": False, "removable": True,
     "options": {"show_legend": True}},
    {"type": "executive_summary", "name": "Executive summary",
     "description": "The plain-English paragraph.",
     "default_title": "Executive summary", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "recommendation", "name": "Reviewer recommendation",
     "description": "What the analyst proposes, separate from what leadership decided.",
     "default_title": "Reviewer recommendation", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "decision", "name": "Decision & conditions",
     "description": "Outcome, rationale, conditions of approval, expiry.",
     "default_title": "Decision", "internal_only": False, "removable": True,
     "options": {"show_conditions": True}},
    {"type": "key_findings", "name": "Key findings",
     "description": "Findings, worst first.",
     "default_title": "Key findings", "internal_only": False, "removable": True,
     "options": {"limit": 5, "show_recommendations": True}},
    {"type": "data_touched", "name": "Data & systems touched",
     "description": "Data classification chips, vendor domain, scope statement.",
     "default_title": "Data & systems touched", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "linked_assets", "name": "In-scope assets",
     "description": "The assets attached to this review with their open-finding counts.",
     "default_title": "In-scope assets", "internal_only": False, "removable": True,
     "options": {"show_finding_counts": True}},
    {"type": "external_checks", "name": "External verification checks",
     "description": "Company posture and technical posture results.",
     "default_title": "External verification checks", "internal_only": False, "removable": True,
     "options": {"show_why_it_matters": True, "panels": "both"}},
    {"type": "interviews", "name": "Stakeholder input",
     "description": "Captured interviews.",
     "default_title": "Stakeholder input", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "attachments", "name": "Supporting documents",
     "description": "Attached contracts, certificates, questionnaire responses.",
     "default_title": "Supporting documents", "internal_only": False, "removable": True,
     "options": {}},
    {"type": "questionnaire", "name": "Technical appendix — questionnaire",
     "description": "Every answered question with evidence and CIS mapping.",
     "default_title": "Technical appendix — questionnaire responses",
     "internal_only": False, "removable": True,
     "options": {"show_evidence": True, "answered_only": True}},
    {"type": "notes", "name": "Analyst working notes",
     "description": "Internal notes. NEVER included in a shared/external report, whatever the template says.",
     "default_title": "Analyst working notes", "internal_only": True, "removable": True,
     "options": {}},
    {"type": "audit_trail", "name": "Audit trail",
     "description": "Every material action taken on the review. Internal only.",
     "default_title": "Audit trail", "internal_only": True, "removable": True,
     "options": {"limit": 50}},
    {"type": "page_break", "name": "Page break",
     "description": "Force the next block onto a new page in print and Word.",
     "default_title": "", "internal_only": False, "removable": True, "options": {}},
    {"type": "section_heading", "name": "Section divider",
     "description": "A titled divider — use it to split the report into parts.",
     "default_title": "Section", "internal_only": False, "removable": True,
     "options": {"subtitle": ""}},
]

BLOCK_BY_TYPE = {b["type"]: b for b in BLOCK_CATALOG}


def _block(btype: str, title: Optional[str] = None, **options) -> dict:
    base = BLOCK_BY_TYPE[btype]
    return {"id": str(uuid.uuid4()), "type": btype,
            "title": title if title is not None else base["default_title"],
            "visible": True, "options": {**base["options"], **options}}


def default_layout() -> list:
    """The stock two-part layout: executive material first, then the technical
    detail, with the questionnaire appendix last -- which is where an appendix
    belongs."""
    return [
        _block("header"),
        _block("section_heading", "Part 1 — Executive summary",
               subtitle="What was reviewed, what the risk is, and what we recommend. "
                        "No technical background required."),
        _block("what_reviewed"),
        _block("risk_verdict"),
        _block("compensating_controls"),
        _block("confidence"),
        _block("executive_summary"),
        _block("recommendation"),
        _block("decision"),
        _block("key_findings"),
        _block("data_touched"),
        _block("page_break"),
        _block("section_heading", "Part 2 — Technical detail",
               subtitle="The evidence behind Part 1: scope, verification results, "
                        "supporting documents and working notes."),
        _block("risk_matrix"),
        _block("linked_assets"),
        _block("external_checks"),
        _block("interviews"),
        _block("attachments"),
        _block("notes"),
        _block("page_break"),
        _block("section_heading", "Appendix",
               subtitle="Full questionnaire responses."),
        _block("questionnaire"),
    ]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


DEFAULT_KEY = "security_review_report"


async def ensure_seeded(db) -> dict:
    existing = await db.report_templates.find(
        {"key": DEFAULT_KEY}, {"_id": 0}).sort("version", -1).to_list(1)
    if existing:
        return existing[0]
    doc = {"id": str(uuid.uuid4()), "key": DEFAULT_KEY,
           "name": "Security Review Report (default)", "version": 1,
           "is_default": True, "blocks": default_layout(),
           "created_by": None, "created_at": _now_iso()}
    await db.report_templates.insert_one(dict(doc))
    return doc


async def active_template(db, key: str = DEFAULT_KEY, template_id: Optional[str] = None) -> dict:
    """The template a report should render under: an explicitly pinned one, else
    the newest version of the default key."""
    if template_id:
        doc = await db.report_templates.find_one({"id": template_id}, {"_id": 0})
        if doc:
            return doc
    docs = await db.report_templates.find({"key": key}, {"_id": 0}).sort("version", -1).to_list(1)
    return docs[0] if docs else await ensure_seeded(db)


def validate_blocks(blocks: list) -> list:
    """Reject unknown block types loudly rather than rendering a blank section,
    and normalize every block so renderers can rely on the shape."""
    if not isinstance(blocks, list) or not blocks:
        raise ValueError("blocks must be a non-empty list")
    out = []
    for i, b in enumerate(blocks):
        btype = (b or {}).get("type")
        if btype not in BLOCK_BY_TYPE:
            raise ValueError(f"Block {i + 1}: unknown block type '{btype}'. "
                              f"Known types: {', '.join(sorted(BLOCK_BY_TYPE))}")
        base = BLOCK_BY_TYPE[btype]
        out.append({
            "id": b.get("id") or str(uuid.uuid4()),
            "type": btype,
            "title": b.get("title", base["default_title"]),
            "visible": bool(b.get("visible", True)),
            "options": {**base["options"], **(b.get("options") or {})},
        })
    if not any(b["type"] == "header" for b in out):
        raise ValueError("The report header block is required")
    return out


def resolve_layout(template: dict, *, shared: bool) -> list:
    """The blocks a renderer should actually draw.

    `shared=True` is the external/vendor-facing copy: internal-only blocks are
    dropped here, centrally, so no template edit and no renderer bug can leak
    working notes or the audit trail outside the organization."""
    blocks = [b for b in (template.get("blocks") or []) if b.get("visible", True)]
    if shared:
        blocks = [b for b in blocks if not BLOCK_BY_TYPE.get(b["type"], {}).get("internal_only")]
    # collapse consecutive/leading/trailing page breaks so an edited layout can't
    # produce a stack of blank pages
    cleaned = []
    for b in blocks:
        if b["type"] == "page_break" and (not cleaned or cleaned[-1]["type"] == "page_break"):
            continue
        cleaned.append(b)
    while cleaned and cleaned[-1]["type"] == "page_break":
        cleaned.pop()
    return cleaned

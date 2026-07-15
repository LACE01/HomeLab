"""Best-effort plain-English summary of a PowerShell command line captured in an
Albert alert's stream data -- answers "what is this command actually doing"
without the analyst having to hand-decode base64 or look up every flag.

Deliberately a heuristic explainer, not a sandboxed/AST-based analyzer: it works
on the text Albert's sensor happened to capture (which may be truncated or
partial), so it flags patterns and decodes what it can rather than claiming to
fully understand the command's behavior.
"""
import base64
import re
from typing import Optional

POWERSHELL_RE = re.compile(r"powershell(?:\.exe)?\b", re.I)

# (flag pattern, plain-English meaning) -- checked against the whole command
# line, not order-sensitive since flags can appear in any order/casing and are
# frequently abbreviated (PowerShell accepts unambiguous prefixes).
FLAG_MEANINGS = [
    (re.compile(r"-nop(?:rofile)?\b", re.I), "Skips loading the user's PowerShell profile (-NoProfile) -- faster startup, and avoids leaving traces in profile-based logging."),
    (re.compile(r"-noni(?:nteractive)?\b", re.I), "Runs non-interactively (-NonInteractive) -- no prompts, suited to unattended/scripted execution rather than a human at a console."),
    (re.compile(r"-nol(?:ogo)?\b", re.I), "Suppresses the PowerShell startup banner (-NoLogo)."),
    (re.compile(r"-w(?:indowstyle)?\s+hidden\b", re.I), "Runs with a hidden window (-WindowStyle Hidden) -- the console isn't shown to the user, common in both legitimate automation and malware trying to avoid detection."),
    (re.compile(r"-ep\s+bypass\b|-executionpolicy\s+bypass\b", re.I), "Bypasses the script execution policy (-ExecutionPolicy Bypass) -- lets otherwise-blocked scripts run for this session only."),
    (re.compile(r"-command\b|-c\s", re.I), "Runs an inline command block (-Command)."),
    (re.compile(r"-encodedcommand\b|-enc\b|-e\s", re.I), "Runs a Base64-encoded command block (-EncodedCommand) -- decoded below."),
    (re.compile(r"-sta\b", re.I), "Runs in single-threaded apartment mode (-STA), required by some COM/UI automation."),
]

# (indicator pattern, {label, risk, explanation}) -- purely heuristic pattern
# matching on the command text, meant to draw attention rather than convict;
# every one of these also has legitimate, benign uses in normal IT scripting.
RISK_INDICATORS = [
    (re.compile(r"invoke-expression|\biex\b", re.I), {
        "label": "Invoke-Expression / IEX", "risk": "High",
        "explanation": "Executes a string as PowerShell code. Extremely common in malicious scripts (it's how a downloaded payload actually gets run), but also used legitimately in some deployment tooling.",
    }),
    (re.compile(r"downloadstring|downloadfile|\biwr\b|invoke-webrequest|net\.webclient|start-bitstransfer", re.I), {
        "label": "Remote download", "risk": "High",
        "explanation": "Fetches content from a remote URL (WebClient/Invoke-WebRequest/BITS). Combined with Invoke-Expression this is the classic \"download cradle\" pattern used to pull down and run a second-stage payload.",
    }),
    (re.compile(r"-bxor|frombase64string|\[convert\]::to", re.I), {
        "label": "Encoding / obfuscation", "risk": "Medium",
        "explanation": "Uses Base64 or XOR-style encoding within the command itself, beyond the standard -EncodedCommand flag -- often used to hide the real payload from simple string-based detection.",
    }),
    (re.compile(r"add-type|reflection\.assembly|\[reflection\.", re.I), {
        "label": "Dynamic code loading", "risk": "Medium",
        "explanation": "Compiles or loads a .NET assembly at runtime -- a way to run compiled code (including shellcode loaders) from within a PowerShell session.",
    }),
    (re.compile(r"amsiutils|amsi.{0,20}bypass|\[ref\]\.assembly", re.I), {
        "label": "Possible AMSI bypass", "risk": "Critical",
        "explanation": "Matches a pattern commonly used to disable the Antimalware Scan Interface (AMSI) so subsequent code isn't scanned -- a strong indicator of intentional evasion.",
    }),
    (re.compile(r"new-object\s+net\.sockets\.tcpclient|invoke-tcpclient", re.I), {
        "label": "Raw socket / reverse shell pattern", "risk": "Critical",
        "explanation": "Opens a raw TCP socket directly from PowerShell -- a common building block for reverse shells.",
    }),
    (re.compile(r"-w(?:indowstyle)?\s+hidden\b", re.I), {
        "label": "Hidden window", "risk": "Medium",
        "explanation": "Runs with no visible console window, which legitimate scheduled/automated tasks do too, but is also a basic way to avoid a user noticing.",
    }),
    (re.compile(r"mimikatz|invoke-mimikatz", re.I), {
        "label": "Credential-dumping tool reference", "risk": "Critical",
        "explanation": "References Mimikatz or a similarly-named function, a well-known credential-dumping tool.",
    }),
]

_RISK_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _decode_encoded_command(command_text: str) -> Optional[str]:
    """Extracts and decodes the Base64 blob following -EncodedCommand/-enc/-e.
    PowerShell's own convention is UTF-16LE for this flag, so that's tried
    first; falls back to UTF-8 and Latin-1 in case the capture is from a
    non-standard invocation (e.g. a cross-platform pwsh script)."""
    m = re.search(r"-(?:encodedcommand|enc|e)\s+([A-Za-z0-9+/=]{16,})", command_text, re.I)
    if not m:
        return None
    blob = m.group(1)
    # Base64 length must be a multiple of 4 -- pad defensively since a truncated
    # network capture may have cut the blob off mid-string.
    blob += "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=False)
    except Exception:
        return None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            # UTF-16LE decode of non-UTF-16 bytes often "succeeds" but produces
            # mostly null/control characters -- a real decode should be mostly
            # printable.
            printable = sum(1 for c in text if c.isprintable())
            if text and printable / max(len(text), 1) > 0.6:
                return text
        except Exception:
            continue
    return None


def analyze_powershell(text: str) -> Optional[dict]:
    """Returns a structured summary if `text` contains a PowerShell invocation,
    otherwise None. `text` is expected to be already-cleaned stream data (see
    albert_ingest._clean_stream_data) but works on raw text too."""
    if not text or not POWERSHELL_RE.search(text):
        return None

    flags_explained = [meaning for pattern, meaning in FLAG_MEANINGS if pattern.search(text)]

    decoded_command = _decode_encoded_command(text)
    # Risk indicators are checked against both the visible command line and the
    # decoded payload (if any) -- an encoded command's real behavior only shows
    # up after decoding.
    scan_text = text + ("\n" + decoded_command if decoded_command else "")
    risk_indicators = []
    seen_labels = set()
    for pattern, info in RISK_INDICATORS:
        if info["label"] in seen_labels:
            continue
        if pattern.search(scan_text):
            risk_indicators.append(info)
            seen_labels.add(info["label"])
    risk_indicators.sort(key=lambda i: _RISK_RANK.get(i["risk"], 9))

    if risk_indicators:
        overall_risk = risk_indicators[0]["risk"]
    else:
        overall_risk = "Low"

    summary_bits = []
    if decoded_command:
        summary_bits.append("Runs a Base64-encoded (obfuscated) command block.")
    if flags_explained:
        summary_bits.append(f"Uses {len(flags_explained)} notable launch flag(s).")
    if risk_indicators:
        labels = ", ".join(i["label"] for i in risk_indicators[:3])
        summary_bits.append(f"Matches pattern(s) worth reviewing: {labels}.")
    else:
        summary_bits.append("No high-risk patterns matched, but review the command text -- this is a heuristic scan, not a verdict.")
    plain_summary = " ".join(summary_bits)

    return {
        "detected": True,
        "command_line": text[:2000],
        "decoded_command": decoded_command[:2000] if decoded_command else None,
        "flags_explained": flags_explained,
        "risk_indicators": risk_indicators,
        "overall_risk": overall_risk,
        "plain_summary": plain_summary,
    }

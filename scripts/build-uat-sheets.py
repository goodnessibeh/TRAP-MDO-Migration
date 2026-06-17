#!/usr/bin/env python3
"""
Build the UAT checklist spreadsheets for this repo (.xlsx only).

Each implementation/test step is exploded onto its own row with a clickable
Done cell (a ☐/☑ data-validation toggle). Story-level columns (User Story,
What We Are Trying to Achieve, Repo References, Expected Results) are merged
once per story group. Styled header (bold white on dark blue), wrapped cells,
thin borders, frozen header, gridlines off.

Repo References use a path relative to the repo root "TRAP-MDO-Migration" so
the sheets import cleanly into forks under different GitHub orgs.

Source of truth:
  * root sheet  -> the committed CSV at HEAD (read via git, URLs -> relative)
  * copilot     -> SC_ROWS below
Outputs:
  * uat-custom-uplift-functionalities.xlsx
  * automation/uat-security-copilot-enhancements.xlsx
"""
import csv
import io
import re
import subprocess
from pathlib import Path

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation

REPO = Path(__file__).resolve().parent.parent
ROOT_XLSX = REPO / "uat-custom-uplift-functionalities.xlsx"
SC_XLSX = REPO / "automation" / "uat-security-copilot-enhancements.xlsx"

SRC_HEADERS = [
    "User Story", "What We Are Trying to Achieve", "Repo References",
    "Implementation Steps", "Test Steps", "Expected Results",
]
OUT_HEADERS = [
    "User Story", "What We Are Trying to Achieve", "Repo References",
    "Phase", "Step", "Done", "Expected Results",
]
WIDTHS = [34, 32, 42, 13, 58, 7, 42]
MERGED_COLS = [1, 2, 3, 7]   # story-level columns (1-indexed)
DONE_COL = 6
UNCHECKED, CHECKED = "⬜", "✅"

URL_RX = re.compile(r"https?://github\.com/[^/\s]+/(?P<repo>[^/\s]+)/(?:blob|tree)/[^/\s]+/(?P<path>\S+)")


def to_relative(text: str) -> str:
    return URL_RX.sub(lambda m: f"{m.group('repo')}/{m.group('path')}", text)


def rel(*parts: str) -> str:
    return "TRAP-MDO-Migration/" + "/".join(parts)


def steps(cell: str):
    return [ln.strip() for ln in (cell or "").splitlines() if ln.strip()]


SC_DOCS = "automation/security-copilot"
# Each entry: [user_story, achieve, repo_refs, impl_steps, test_steps, expected]
SC_ROWS = [
    [
        "As a SOC analyst, I want user-reported phishing emails autonomously triaged and "
        "classified as a real threat or a false alarm before they reach my queue, so I stop "
        "spending ~30 minutes reading false alarms.",
        "Insert an autonomous LLM triage tier (Security Copilot Phishing Triage Agent) ahead of "
        "the analyst: auto-resolve false positives, keep true positives open and tagged with a "
        "transparent rationale.",
        "\n".join([rel(SC_DOCS, "01-phishing-triage-agent.md"), rel(SC_DOCS, "README.md"),
                   rel("08-abuse-mailbox-and-user-reporting.md")]),
        "\n".join([
            "1. Confirm MDO Plan 2 and a Security Copilot SCU entitlement (E5 inclusion or provisioned).",
            "2. Enable Unified RBAC (URBAC) for Defender for Office 365.",
            "3. Enable 'Monitor reported messages in Outlook' and the reported-phish alert policy.",
            "4. Disable the 'Auto-Resolve - Email reported by user as malware or phish' tuning rule.",
            "5. Run the agent setup wizard; assign an Entra Agent ID with the five Security operations permissions scoped to the MDO data source.",
            "6. Run the agent in observe mode through the Phase 2 parallel run.",
        ]),
        "\n".join([
            "1. Submit one known-benign report and one known-phish simulation via the Report button.",
            "2. Confirm the agent triggers on the reported-phish alert and self-assigns.",
            "3. Open each incident and review the agent verdict, evidence, and decision-tree.",
            "4. Confirm the false positive is auto-resolved and the true positive stays open and Agent-tagged.",
        ]),
        "\n".join([
            "Benign report auto-resolved as False Positive with a plain-language rationale.",
            "Phish simulation classified True Positive; incident open with the Agent tag and a viewable decision-tree.",
            "Analyst queue shows only true positives.",
        ]),
    ],
    [
        "As a SOC analyst, I want to correct a wrong agent verdict in plain language and have the "
        "agent learn from it, so our organisation's context shapes future triage.",
        "Provide a CLEAR-equivalent analyst tuning loop via stored, per-organisation feedback lessons.",
        "\n".join([rel(SC_DOCS, "01-phishing-triage-agent.md"), rel("03-trap-capability-matrix.md")]),
        "\n".join([
            "1. On a misclassified alert, select 'Change classification'.",
            "2. Enter specific, contextual feedback (sender domain, subject pattern, recipient pattern).",
            "3. Select 'Evaluate feedback' and review the generated lesson.",
            "4. Select 'Use this feedback to teach the agent' and Save.",
            "5. Seed initial lessons for finance, benefits, HR, and file-share sender domains.",
        ]),
        "\n".join([
            "1. Add a lesson, e.g. 'benefits mail must originate from @benefits.<our-domain>'.",
            "2. Submit a new report that violates the lesson.",
            "3. Open the feedback management page and check the lesson status.",
        ]),
        "\n".join([
            "Lesson stored with status 'In use'.",
            "Subsequent matching alert classified per the lesson, with the lesson cited as evidence.",
            "All feedback logged for audit whether or not promoted to a lesson.",
        ]),
    ],
    [
        "As a SOC analyst, I want a plain-language incident summary and next-best-action "
        "recommendations on each incident, so I cut read-in time and act faster.",
        "Stand up the embedded read-side Copilot experiences (incident summarisation and guided "
        "response) in Defender XDR and Sentinel.",
        "\n".join([rel(SC_DOCS, "02-copilot-in-defender-and-sentinel.md"),
                   rel("06-sentinel-soar-orchestration.md"), rel("05-defender-xdr-air-zap.md")]),
        "\n".join([
            "1. Onboard Sentinel to the Defender portal so incidents unify.",
            "2. Confirm Copilot in Defender is enabled for the tenant.",
            "3. Open a phishing incident, generate the summary, and review guided response.",
        ]),
        "\n".join([
            "1. Open a representative phishing incident.",
            "2. Generate the Copilot incident summary.",
            "3. Request an executive (non-technical) incident report.",
        ]),
        "\n".join([
            "One-paragraph summary fusing internal telemetry with Microsoft Threat Intelligence.",
            "Guided-response next-best actions listed against the incident.",
            "Executive report generated, suitable for a non-technical audience.",
        ]),
    ],
    [
        "As a SOC analyst, I want to express ad-hoc hunts in plain English and have Copilot generate "
        "the KQL against our tables, so long-tail hunts do not need hand-written queries.",
        "Enable natural-language-to-KQL for Sentinel and Defender advanced hunting as an accelerator "
        "over the curated KQL library.",
        "\n".join([rel(SC_DOCS, "02-copilot-in-defender-and-sentinel.md"), rel("09-kql-detection-library.md")]),
        "\n".join([
            "1. Configure a default Sentinel workspace for Copilot under Sources.",
            "2. Enable the 'Microsoft Sentinel (Preview)' and 'Natural language to KQL for Microsoft Sentinel (Preview)' plugins.",
            "3. Prompt Copilot from the advanced-hunting surface.",
        ]),
        "\n".join([
            "1. Prompt: 'show all mail from sender X to VIP users in the last 3 days'.",
            "2. Run the generated KQL.",
            "3. Compare output to the curated Q-library equivalent in doc 09.",
        ]),
        "\n".join([
            "Valid KQL generated against EmailEvents / EmailUrlInfo and runs without error.",
            "Results return; analyst can refine and promote a good hunt into doc 09.",
        ]),
    ],
    [
        "As a SOC analyst, I want saved promptbooks for our recurring workflows, so triage and "
        "reporting are repeatable.",
        "Operationalise the project promptbook library (PB-A..PB-F), each paired to a playbook P1-P7.",
        "\n".join([rel(SC_DOCS, "03-promptbook-library.md"), rel("10-logic-apps-playbook-library.md")]),
        "\n".join([
            "1. In the standalone portal, refine each PB-x prompt set against a real incident.",
            "2. Save each set as a promptbook using its PB-x name.",
            "3. Parameterise inputs (IncidentId, NetworkMessageId, DLAddress, IOC).",
        ]),
        "\n".join([
            "1. Run PB-A (user-reported phishing investigation) on a true-positive incident.",
            "2. Run PB-D (TI retroactive sweep) with a test IOC.",
        ]),
        "\n".join([
            "Promptbook returns the structured investigation / report.",
            "Parameters fill cleanly; SCU cost per run is visible on the usage dashboard.",
        ]),
    ],
    [
        "As a security lead, I want to confirm our Security Copilot entitlement and size SCU capacity "
        "from real usage, so we adopt Copilot at predictable cost.",
        "Adopt on E5 inclusion first and measure cost-per-email before provisioning any SCUs.",
        "\n".join([rel(SC_DOCS, "04-licensing-scu-governance.md"), rel("13-licensing-and-operations.md")]),
        "\n".join([
            "1. Confirm the E5 inclusion allocation (400 SCUs/month per 1,000 paid E5 licences, capped at 10,000).",
            "2. Run the agent trial; read cost-per-email on the Performance tab.",
            "3. Multiply by daily reported-mail volume; add embedded/promptbook usage from the usage dashboard.",
            "4. Decide provisioned SCUs vs pay-as-you-go and record it in doc 13.",
        ]),
        "\n".join([
            "1. Export the usage-monitoring dashboard to Excel, filtered to agent operations.",
            "2. Compute steady-state SCU demand and compare against the inclusion allocation.",
        ]),
        "\n".join([
            "Documented SCU demand vs allocation.",
            "No provisioning required if demand is within the inclusion allocation; decision recorded in doc 13.",
        ]),
    ],
    [
        "As a security admin, I want the autonomous agent to run under a scoped, least-privilege "
        "identity with full audit, so automation stays inside our governance model.",
        "Run the agent under an Entra Agent ID with least privilege, Purview audit of every decision, "
        "and admin pause/remove control.",
        "\n".join([rel(SC_DOCS, "04-licensing-scu-governance.md"), rel(SC_DOCS, "01-phishing-triage-agent.md")]),
        "\n".join([
            "1. Create a new Entra Agent ID during agent setup.",
            "2. Assign a role with only the five Security operations permissions, scoped to the MDO data source.",
            "3. Give the oversight group permissions equal to or greater than the agent's.",
            "4. Confirm decisions and feedback are written to Microsoft Purview audit.",
        ]),
        "\n".join([
            "1. Review the agent identity and role on the Defender Permissions page.",
            "2. Verify agent decisions appear in Purview audit logs.",
            "3. Pause the agent and confirm triage stops.",
        ]),
        "\n".join([
            "Agent holds only the five scoped permissions on the MDO data source.",
            "Every decision is in Purview audit with a viewable decision-tree.",
            "Pause/remove works; the oversight group can review all activity.",
        ]),
    ],
    [
        "As a SOC lead, I want confirmed low-risk phish to remediate without a human keystroke while "
        "VIP, irreversible, and novel cases still gate, so we eliminate toil but keep controls.",
        "Add a conditional auto-approve rule between the agent's True-Positive verdict and the "
        "remediation playbooks, generalising the P2 watchlist short-circuit.",
        "\n".join([rel(SC_DOCS, "05-zero-touch-phishing-pipeline.md"),
                   rel("automation/logic-apps/P2-ti-sweep-remediate/README.md"),
                   rel("automation/logic-apps/P6-two-stage-approval-vip/README.md")]),
        "\n".join([
            "1. Build a Sentinel automation rule between the agent TP verdict and the remediation playbook.",
            "2. Auto-approve only when the sender/URL/hash is on a KnownBad_* watchlist, no VIP is touched, and the action is reversible (soft-delete).",
            "3. Route VIP, irreversible, or novel-campaign cases to the P6 two-stage human gate.",
            "4. Promote judged novel campaigns to a watchlist entry or an agent lesson.",
        ]),
        "\n".join([
            "1. Fire a true positive matching a KnownBad watchlist with no VIP recipient.",
            "2. Fire a true positive that touches a VIP/VAP watchlist member.",
            "3. Fire a novel campaign with no prior watchlist or lesson match.",
        ]),
        "\n".join([
            "In-policy case soft-deleted with no human click and an incident comment posted.",
            "VIP case waits for two-stage approval (P6).",
            "Novel case is gated once, then automatic thereafter; auto-approve rate rises over time.",
        ]),
    ],
]


def read_root_matrix():
    """Read the committed root CSV from git HEAD and relativise the repo column."""
    raw = subprocess.run(
        ["git", "show", "HEAD:uat-custom-uplift-functionalities.csv"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    rows = list(csv.reader(io.StringIO(raw)))
    ref = rows[0].index("Repo References")
    for r in rows[1:]:
        r[ref] = to_relative(r[ref])
    return rows[1:]   # data rows only


def build_checklist(stories, xlsx_path: Path, title: str):
    """stories: list of 6-field rows. Explode steps into rows with a Done toggle."""
    wb = Workbook()
    ws = wb.active
    ws.title = title

    header_fill = PatternFill("solid", fgColor="2E7D32")
    band_fill = PatternFill("solid", fgColor="E8F5E9")
    header_font = Font(bold=True, color="FFFFFF", size=11)
    body_font = Font(size=10)
    phase_font = Font(size=10, bold=True, color="2E7D32")
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    h_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    story_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
    step_align = Alignment(horizontal="left", vertical="center", wrap_text=True)
    done_align = Alignment(horizontal="center", vertical="center")

    for i, w in enumerate(WIDTHS, start=1):
        ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w

    # header
    for c, val in enumerate(OUT_HEADERS, start=1):
        cell = ws.cell(row=1, column=c, value=val)
        cell.fill, cell.font, cell.alignment, cell.border = header_fill, header_font, h_align, border
    ws.row_dimensions[1].height = 30

    dv = DataValidation(type="list", formula1=f'"{UNCHECKED},{CHECKED}"', allow_blank=False)
    ws.add_data_validation(dv)

    r = 2
    for si, story in enumerate(stories):
        us, achieve, refs, impl, tests, expected = story
        rows = [("Implementation", s) for s in steps(impl)] + [("Test", s) for s in steps(tests)]
        if not rows:
            rows = [("", "")]
        start = r
        band = band_fill if si % 2 else None
        for phase, step in rows:
            ws.cell(row=r, column=4, value=phase)
            ws.cell(row=r, column=5, value=step)
            done = ws.cell(row=r, column=DONE_COL, value=UNCHECKED)
            dv.add(done)
            r += 1
        end = r - 1
        # story-level merged columns
        for col, val in ((1, us), (2, achieve), (3, refs), (7, expected)):
            ws.cell(row=start, column=col, value=val)
            if end > start:
                ws.merge_cells(start_row=start, start_column=col, end_row=end, end_column=col)
        # style the whole block
        for rr in range(start, end + 1):
            for cc in range(1, len(OUT_HEADERS) + 1):
                cell = ws.cell(row=rr, column=cc)
                cell.border = border
                if band:
                    cell.fill = band
                if cc in MERGED_COLS:
                    cell.font, cell.alignment = body_font, story_align
                elif cc == 4:
                    cell.font, cell.alignment = phase_font, step_align
                elif cc == DONE_COL:
                    cell.font, cell.alignment = body_font, done_align
                else:
                    cell.font, cell.alignment = body_font, step_align

    # Strike through the step text when its Done cell is checked.
    last = ws.max_row
    if last >= 2:
        strike = Font(strike=True, color="9E9E9E", size=10)
        ws.conditional_formatting.add(
            f"D2:E{last}",
            FormulaRule(formula=[f'$F2="{CHECKED}"'], font=strike),
        )

    ws.freeze_panes = "A2"
    ws.sheet_view.showGridLines = False
    wb.save(xlsx_path)
    return ws.max_row


def main():
    n1 = build_checklist(read_root_matrix(), ROOT_XLSX, "Custom Uplift UAT")
    n2 = build_checklist(SC_ROWS, SC_XLSX, "Security Copilot UAT")
    print(f"root xlsx: {ROOT_XLSX.relative_to(REPO)}  ({n1} rows incl header)")
    print(f"sc   xlsx: {SC_XLSX.relative_to(REPO)}  ({n2} rows incl header)")


if __name__ == "__main__":
    main()

# Sentinel Workbooks

JSON workbook definitions for the TRAP → MDO migration. Import each
into a Sentinel workspace via **Microsoft Sentinel → Workbooks → Add
workbook → Advanced editor → Gallery template**.

## Shipped workbooks

| Workbook | Purpose | Phase |
|---|---|---|
| `mdo-operational-dashboard.json` | Daily SOC view: inbound counts by verdict, post-delivery actions (ZAP/AIR), user-reported volume, top reporters, Action Center activity, top delivered-phish sender domains | Phase 1 onwards |
| `trap-mdo-parallel-run.json` | Side-by-side comparison framework for Phase 2 — MTTR, FP rate, AIR verdict mix, gap-candidate counts that drive the Phase 3 build decision | Phase 2 only |

Both have been validated against the static checker in
`../tests/Test-WorkbookSchema.ps1`.

## Import

Per workbook:

1. Sentinel → Workbooks → **+ Add workbook**.
2. **Edit** → **Advanced editor** (the `</>` icon top right).
3. Switch the Template Type to **Gallery Template**.
4. Paste the JSON contents → **Apply**.
5. **Done editing**.
6. **Save** with a meaningful title and the resource group of your
   workspace.

Required parameters (`Workspace`, `TimeRange`) auto-prompt at the top
of every workbook. `Workspace` lets you point at any LA workspace the
viewer has access to.

## Required data streams

Both workbooks depend on these Sentinel tables — make sure the
Microsoft Defender XDR data connector has them enabled:

* `EmailEvents`
* `EmailPostDeliveryEvents`
* `AlertInfo`
* `AlertEvidence`

Plus the **Office 365** data connector for `OfficeActivity`. The MTTR
and quarantine-release panels need it.

## Validate

```powershell
.\automation\tests\Test-WorkbookSchema.ps1 -Path .\automation\workbooks
```

The validator checks JSON shape, required item fields per item type,
and that every `{ParamName}` referenced by a query is declared in at
least one type-9 parameters block.

## Adding your own

Place the new `<name>.json` here. The validator picks up every `.json`
under this directory automatically. Use the existing two as templates
— the parameters block at the top + a TimeRange/Workspace pair covers
most needs.

## Workbooks that are NOT shipped here

The blueprint suggests a few more workbooks that you might want
eventually but they need organisation-specific tuning before shipping:

* **VAP-touch view** — depends on a VAP watchlist that varies by
  business. Build once you've curated the list.
* **Reporter precision scoreboard** — depends on a verdict-labelled
  history of past reports. Useful once you have ≥3 months of report
  data.
* **Audit trail of every pull** — already covered by Sentinel's
  Incident audit timeline + Action Center History. Build the workbook
  only if you have an external compliance requirement that needs the
  audit data outside Defender.

See [`13-licensing-and-operations.md`](../../13-licensing-and-operations.md)
for the design notes on these.

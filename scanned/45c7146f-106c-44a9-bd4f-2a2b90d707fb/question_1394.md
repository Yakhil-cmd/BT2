# Q1394: wallet-send via mojoToChiaLocaleString 1394

## Question
Can an unprivileged attacker entering through the wallet send form submission in `mojoToChiaLocaleString` (packages/gui/src/electron/utils/mojoToChiaLocaleString.ts) control amount and fee strings near precision boundaries with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToChiaLocaleString.ts` / `mojoToChiaLocaleString`
- Entrypoint: wallet send form submission
- Attacker controls: amount and fee strings near precision boundaries; with precision-boundary values
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

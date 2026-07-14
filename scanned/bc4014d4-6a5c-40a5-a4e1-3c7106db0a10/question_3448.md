# Q3448: wallet-send via fromBech32m 3448

## Question
Can an unprivileged attacker entering through the CAT send form submission in `fromBech32m` (packages/gui/src/electron/utils/toBech32m.ts) control destination address with mixed prefix/case or hidden characters with a delayed metadata fetch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/toBech32m.ts` / `fromBech32m`
- Entrypoint: CAT send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; with a delayed metadata fetch
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

# Q1506: wallet-send via normalizeHex 1506

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `normalizeHex` (packages/api/src/utils/normalizeHex.ts) control stale walletId from route or dropdown state with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: stale walletId from route or dropdown state; with a redirected remote resource
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

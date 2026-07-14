# Q462: wallet-send via normalizeHex 462

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `normalizeHex` (packages/gui/src/electron/utils/normalizeHex.ts) control destination address with mixed prefix/case or hidden characters with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: destination address with mixed prefix/case or hidden characters; with hidden Unicode characters
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

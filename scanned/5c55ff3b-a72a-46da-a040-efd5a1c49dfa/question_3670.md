# Q3670: wallet-send via validAddress 3670

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `validAddress` (packages/core/src/utils/validAddress.ts) control destination address with mixed prefix/case or hidden characters with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/validAddress.ts` / `validAddress`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: destination address with mixed prefix/case or hidden characters; with reordered RPC events
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

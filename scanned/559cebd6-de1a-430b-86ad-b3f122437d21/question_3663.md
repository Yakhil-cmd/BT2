# Q3663: wallet-send via chiaToMojo 3663

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `chiaToMojo` (packages/core/src/utils/chiaToMojo.ts) control destination address with mixed prefix/case or hidden characters after a profile switch and drive the sequence import -> parse -> preview -> submit so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/chiaToMojo.ts` / `chiaToMojo`
- Entrypoint: wallet RPC send command
- Attacker controls: destination address with mixed prefix/case or hidden characters; after a profile switch
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

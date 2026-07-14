# Q3263: wallet-send via mojoToChiaLocaleString 3263

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `mojoToChiaLocaleString` (packages/gui/src/electron/utils/mojoToChiaLocaleString.ts) control clawback timelock fields combined with normal send fields after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToChiaLocaleString.ts` / `mojoToChiaLocaleString`
- Entrypoint: wallet RPC send command
- Attacker controls: clawback timelock fields combined with normal send fields; after a profile switch
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

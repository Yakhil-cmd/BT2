# Q867: wallet-send via mojoToChiaLocaleString 867

## Question
Can an unprivileged attacker entering through the wallet send form submission in `mojoToChiaLocaleString` (packages/core/src/utils/mojoToChiaLocaleString.ts) control destination address with mixed prefix/case or hidden characters with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/mojoToChiaLocaleString.ts` / `mojoToChiaLocaleString`
- Entrypoint: wallet send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; with a cached permission entry
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

# Q1635: wallet-send via if 1635

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `if` (packages/gui/src/util/parseFee.ts) control amount and fee strings near precision boundaries with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/util/parseFee.ts` / `if`
- Entrypoint: fee and amount conversion path
- Attacker controls: amount and fee strings near precision boundaries; with a delayed metadata fetch
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

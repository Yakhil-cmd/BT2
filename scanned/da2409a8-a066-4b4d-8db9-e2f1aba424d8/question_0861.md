# Q861: wallet-send via chiaToMojo 861

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `chiaToMojo` (packages/core/src/utils/chiaToMojo.ts) control amount and fee strings near precision boundaries during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse stale balance/sync state to authorize a spend that should be blocked, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/chiaToMojo.ts` / `chiaToMojo`
- Entrypoint: fee and amount conversion path
- Attacker controls: amount and fee strings near precision boundaries; during a pending modal confirmation
- Exploit idea: reuse stale balance/sync state to authorize a spend that should be blocked
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

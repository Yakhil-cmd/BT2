# Q866: wallet-send via mojoToChia 866

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `mojoToChia` (packages/core/src/utils/mojoToChia.ts) control stale walletId from route or dropdown state during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: fee and amount conversion path
- Attacker controls: stale walletId from route or dropdown state; during a pending modal confirmation
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

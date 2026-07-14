# Q3158: wallet-send via farm 3158

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `farm` (packages/wallets/src/components/WalletSend.tsx) control amount and fee strings near precision boundaries after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/WalletSend.tsx` / `farm`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: amount and fee strings near precision boundaries; after a failed RPC response
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

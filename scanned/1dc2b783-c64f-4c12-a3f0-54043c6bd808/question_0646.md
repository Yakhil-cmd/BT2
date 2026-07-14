# Q646: wallet-send via removePrefix 646

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `removePrefix` (packages/gui/src/electron/utils/toBech32m.ts) control rapid wallet/profile switching during submit with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/toBech32m.ts` / `removePrefix`
- Entrypoint: wallet RPC send command
- Attacker controls: rapid wallet/profile switching during submit; with a duplicate identifier
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

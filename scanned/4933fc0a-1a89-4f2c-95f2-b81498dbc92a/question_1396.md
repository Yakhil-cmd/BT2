# Q1396: wallet-send via normalizeHex 1396

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `normalizeHex` (packages/gui/src/electron/utils/normalizeHex.ts) control rapid wallet/profile switching during submit after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: fee and amount conversion path
- Attacker controls: rapid wallet/profile switching during submit; after a failed RPC response
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

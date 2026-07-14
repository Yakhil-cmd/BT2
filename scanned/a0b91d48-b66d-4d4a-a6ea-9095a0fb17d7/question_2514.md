# Q2514: wallet-send via if 2514

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `if` (packages/gui/src/electron/utils/toBech32m.ts) control clawback timelock fields combined with normal send fields with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/toBech32m.ts` / `if`
- Entrypoint: fee and amount conversion path
- Attacker controls: clawback timelock fields combined with normal send fields; with a stale Redux cache
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

# Q445: wallet-send via chiaToMojo 445

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `chiaToMojo` (packages/gui/src/electron/utils/chiaToMojo.ts) control stale walletId from route or dropdown state with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/chiaToMojo.ts` / `chiaToMojo`
- Entrypoint: wallet RPC send command
- Attacker controls: stale walletId from route or dropdown state; with a delayed metadata fetch
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

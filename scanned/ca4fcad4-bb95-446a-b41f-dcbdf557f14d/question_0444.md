# Q444: wallet-send via chiaToMojo 444

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `chiaToMojo` (packages/gui/src/electron/utils/chiaToMojo.ts) control rapid wallet/profile switching during submit with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would drop or alter clawback restrictions while still showing a clawback-protected send, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/chiaToMojo.ts` / `chiaToMojo`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: rapid wallet/profile switching during submit; with a delayed metadata fetch
- Exploit idea: drop or alter clawback restrictions while still showing a clawback-protected send
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

# Q2224: wallet-send via if 2224

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `if` (packages/wallets/src/components/WalletSend.tsx) control stale walletId from route or dropdown state with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that address validation and displayed destination must be canonical and network-correct, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/WalletSend.tsx` / `if`
- Entrypoint: wallet RPC send command
- Attacker controls: stale walletId from route or dropdown state; with hidden Unicode characters
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: address validation and displayed destination must be canonical and network-correct
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

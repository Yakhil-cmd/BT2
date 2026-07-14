# Q3488: wallet-send via wallet 3488

## Question
Can an unprivileged attacker entering through the wallet send form submission in `wallet` (packages/gui/src/hooks/useStandardWallet.ts) control stale walletId from route or dropdown state with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/hooks/useStandardWallet.ts` / `wallet`
- Entrypoint: wallet send form submission
- Attacker controls: stale walletId from route or dropdown state; with hidden Unicode characters
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

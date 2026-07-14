# Q686: wallet-send via useStandardWallet 686

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `useStandardWallet` (packages/gui/src/hooks/useStandardWallet.ts) control destination address with mixed prefix/case or hidden characters with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/hooks/useStandardWallet.ts` / `useStandardWallet`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: destination address with mixed prefix/case or hidden characters; with case-normalized identifiers
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

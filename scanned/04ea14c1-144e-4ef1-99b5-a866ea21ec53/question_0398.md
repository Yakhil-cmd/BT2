# Q398: wallet-send via WalletCATSend 398

## Question
Can an unprivileged attacker entering through the wallet send form submission in `WalletCATSend` (packages/wallets/src/components/cat/WalletCATSend.tsx) control destination address with mixed prefix/case or hidden characters with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/wallets/src/components/cat/WalletCATSend.tsx` / `WalletCATSend`
- Entrypoint: wallet send form submission
- Attacker controls: destination address with mixed prefix/case or hidden characters; with case-normalized identifiers
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

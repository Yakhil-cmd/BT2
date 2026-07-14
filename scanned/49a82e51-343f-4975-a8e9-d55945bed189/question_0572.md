# Q572: wallet-send via normalizeHex 572

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `normalizeHex` (packages/api/src/utils/normalizeHex.ts) control rapid wallet/profile switching during submit with case-normalized identifiers and drive the sequence open notification -> resolve details -> execute so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/normalizeHex.ts` / `normalizeHex`
- Entrypoint: wallet RPC send command
- Attacker controls: rapid wallet/profile switching during submit; with case-normalized identifiers
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

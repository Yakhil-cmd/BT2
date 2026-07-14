# Q459: wallet-send via mojoToChia 459

## Question
Can an unprivileged attacker entering through the receive-address copy/new-address flow in `mojoToChia` (packages/gui/src/electron/utils/mojoToChia.ts) control rapid wallet/profile switching during submit with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would round or normalize amount/fee differently between display and RPC payload, violating the invariant that confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: receive-address copy/new-address flow
- Attacker controls: rapid wallet/profile switching during submit; with a duplicate identifier
- Exploit idea: round or normalize amount/fee differently between display and RPC payload
- Invariant to test: confirmed walletId, assetId, amount, fee, address, and clawback settings must exactly match the RPC transaction payload
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

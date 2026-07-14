# Q3668: wallet-send via mojoToChia 3668

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `mojoToChia` (packages/core/src/utils/mojoToChia.ts) control rapid wallet/profile switching during submit after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would make the GUI submit a spend for a different wallet or asset than the confirmation showed, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/core/src/utils/mojoToChia.ts` / `mojoToChia`
- Entrypoint: wallet RPC send command
- Attacker controls: rapid wallet/profile switching during submit; after a network switch
- Exploit idea: make the GUI submit a spend for a different wallet or asset than the confirmation showed
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

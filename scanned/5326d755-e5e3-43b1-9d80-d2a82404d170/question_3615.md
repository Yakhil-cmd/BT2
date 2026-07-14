# Q3615: wallet-send via fromBech32m 3615

## Question
Can an unprivileged attacker entering through the wallet RPC send command in `fromBech32m` (packages/api/src/utils/toBech32m.ts) control destination address with mixed prefix/case or hidden characters after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/toBech32m.ts` / `fromBech32m`
- Entrypoint: wallet RPC send command
- Attacker controls: destination address with mixed prefix/case or hidden characters; after canceling and reopening the dialog
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

# Q813: wallet-send via removePrefix 813

## Question
Can an unprivileged attacker entering through the fee and amount conversion path in `removePrefix` (packages/api/src/utils/toBech32m.ts) control rapid wallet/profile switching during submit through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would accept an address that displays as one target but serializes as another, violating the invariant that send buttons must not execute while wallet identity, sync state, or fee inputs are stale, leading to Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT?

## Target
- File/function: `packages/api/src/utils/toBech32m.ts` / `removePrefix`
- Entrypoint: fee and amount conversion path
- Attacker controls: rapid wallet/profile switching during submit; through a batch of rapid user-accessible actions
- Exploit idea: accept an address that displays as one target but serializes as another
- Invariant to test: send buttons must not execute while wallet identity, sync state, or fee inputs are stale
- Expected Immunefi impact: Critical: unauthorized spend, transfer, clawback bypass, or wrong-asset balance change affecting XCH, CAT, or CR-CAT
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

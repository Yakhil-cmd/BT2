# Q3494: did-vc-datalayer via didFromDIDId 3494

## Question
Can an unprivileged attacker entering through the DataLayer offer take/cancel flow in `didFromDIDId` (packages/gui/src/util/dids.ts) control VC proof/revoke payload from notification or RPC state with conflicting localStorage preferences and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mix DataLayer offer summary with normal offer acceptance path, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/util/dids.ts` / `didFromDIDId`
- Entrypoint: DataLayer offer take/cancel flow
- Attacker controls: VC proof/revoke payload from notification or RPC state; with conflicting localStorage preferences
- Exploit idea: mix DataLayer offer summary with normal offer acceptance path
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

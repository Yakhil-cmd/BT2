# Q3389: did-vc-datalayer via SigningEntityDID 3389

## Question
Can an unprivileged attacker entering through the DataLayer offer take/cancel flow in `SigningEntityDID` (packages/gui/src/components/signVerify/SigningEntityDID.tsx) control DID identifier with alternate format or stale wallet mapping with a cached permission entry and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept or revoke based on spoofed proof/store state, violating the invariant that external mirror/subscription data must not bypass confirmation, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityDID.tsx` / `SigningEntityDID`
- Entrypoint: DataLayer offer take/cancel flow
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with a cached permission entry
- Exploit idea: accept or revoke based on spoofed proof/store state
- Invariant to test: external mirror/subscription data must not bypass confirmation
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

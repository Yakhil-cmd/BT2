# Q3696: did-vc-datalayer via loadProofsData 3696

## Question
Can an unprivileged attacker entering through the DataLayer offer take/cancel flow in `loadProofsData` (packages/gui/src/components/vcs/VCList.tsx) control DID identifier with alternate format or stale wallet mapping with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would accept or revoke based on spoofed proof/store state, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCList.tsx` / `loadProofsData`
- Entrypoint: DataLayer offer take/cancel flow
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with case-normalized identifiers
- Exploit idea: accept or revoke based on spoofed proof/store state
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

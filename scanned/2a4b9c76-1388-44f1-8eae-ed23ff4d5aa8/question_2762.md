# Q2762: did-vc-datalayer via handleScrollRef 2762

## Question
Can an unprivileged attacker entering through the DataLayer store key update in `handleScrollRef` (packages/gui/src/components/vcs/VCList.tsx) control DID identifier with alternate format or stale wallet mapping with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would persist a malicious mirror/subscription that later drives unsafe content or wallet action, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCList.tsx` / `handleScrollRef`
- Entrypoint: DataLayer store key update
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with a delayed metadata fetch
- Exploit idea: persist a malicious mirror/subscription that later drives unsafe content or wallet action
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

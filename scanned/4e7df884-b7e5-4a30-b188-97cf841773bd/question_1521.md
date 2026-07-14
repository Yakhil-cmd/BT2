# Q1521: did-vc-datalayer via handleProfileSelected 1521

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `handleProfileSelected` (packages/gui/src/components/signVerify/SigningEntityDID.tsx) control DataLayer offer summary with conflicting store IDs with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would submit a batch update whose displayed keys differ from RPC payload keys, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityDID.tsx` / `handleProfileSelected`
- Entrypoint: mirror/subscription action
- Attacker controls: DataLayer offer summary with conflicting store IDs; with a delayed metadata fetch
- Exploit idea: submit a batch update whose displayed keys differ from RPC payload keys
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

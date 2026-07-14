# Q1626: did-vc-datalayer via didFromDIDId 1626

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `didFromDIDId` (packages/gui/src/util/dids.ts) control batch update keys and values with duplicated encodings with a stale Redux cache and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would persist a malicious mirror/subscription that later drives unsafe content or wallet action, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/util/dids.ts` / `didFromDIDId`
- Entrypoint: mirror/subscription action
- Attacker controls: batch update keys and values with duplicated encodings; with a stale Redux cache
- Exploit idea: persist a malicious mirror/subscription that later drives unsafe content or wallet action
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

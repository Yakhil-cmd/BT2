# Q3694: did-vc-datalayer via handleKeyDown 3694

## Question
Can an unprivileged attacker entering through the DID profile dropdown/change flow in `handleKeyDown` (packages/gui/src/components/vcs/VCEditTitle.tsx) control mirror URL and subscription data from untrusted input with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would apply a DID/VC/DataLayer action to a different wallet or store than displayed, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCEditTitle.tsx` / `handleKeyDown`
- Entrypoint: DID profile dropdown/change flow
- Attacker controls: mirror URL and subscription data from untrusted input; with a redirected remote resource
- Exploit idea: apply a DID/VC/DataLayer action to a different wallet or store than displayed
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

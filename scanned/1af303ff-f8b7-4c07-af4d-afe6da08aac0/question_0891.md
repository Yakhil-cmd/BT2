# Q891: did-vc-datalayer via VCDetail 891

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `VCDetail` (packages/gui/src/components/vcs/VCDetail.tsx) control mirror URL and subscription data from untrusted input through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mix DataLayer offer summary with normal offer acceptance path, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCDetail.tsx` / `VCDetail`
- Entrypoint: mirror/subscription action
- Attacker controls: mirror URL and subscription data from untrusted input; through a batch of rapid user-accessible actions
- Exploit idea: mix DataLayer offer summary with normal offer acceptance path
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

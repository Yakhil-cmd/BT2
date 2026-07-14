# Q3693: did-vc-datalayer via renderVCCard 3693

## Question
Can an unprivileged attacker entering through the VC revoke/spend/proof action in `renderVCCard` (packages/gui/src/components/vcs/VCDetail.tsx) control DataLayer offer summary with conflicting store IDs after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mix DataLayer offer summary with normal offer acceptance path, violating the invariant that external mirror/subscription data must not bypass confirmation, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCDetail.tsx` / `renderVCCard`
- Entrypoint: VC revoke/spend/proof action
- Attacker controls: DataLayer offer summary with conflicting store IDs; after canceling and reopening the dialog
- Exploit idea: mix DataLayer offer summary with normal offer acceptance path
- Invariant to test: external mirror/subscription data must not bypass confirmation
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

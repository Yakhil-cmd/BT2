# Q895: did-vc-datalayer via VCRevokeDialog 895

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `VCRevokeDialog` (packages/gui/src/components/vcs/VCRevokeDialog.tsx) control DataLayer offer summary with conflicting store IDs during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would submit a batch update whose displayed keys differ from RPC payload keys, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCRevokeDialog.tsx` / `VCRevokeDialog`
- Entrypoint: mirror/subscription action
- Attacker controls: DataLayer offer summary with conflicting store IDs; during a pending modal confirmation
- Exploit idea: submit a batch update whose displayed keys differ from RPC payload keys
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

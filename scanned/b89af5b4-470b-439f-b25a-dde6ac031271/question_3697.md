# Q3697: did-vc-datalayer via VCRevokeDialog 3697

## Question
Can an unprivileged attacker entering through the VC revoke/spend/proof action in `VCRevokeDialog` (packages/gui/src/components/vcs/VCRevokeDialog.tsx) control VC proof/revoke payload from notification or RPC state after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a malicious mirror/subscription that later drives unsafe content or wallet action, violating the invariant that external mirror/subscription data must not bypass confirmation, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCRevokeDialog.tsx` / `VCRevokeDialog`
- Entrypoint: VC revoke/spend/proof action
- Attacker controls: VC proof/revoke payload from notification or RPC state; after a network switch
- Exploit idea: persist a malicious mirror/subscription that later drives unsafe content or wallet action
- Invariant to test: external mirror/subscription data must not bypass confirmation
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

# Q890: did-vc-datalayer via RenderProperty 890

## Question
Can an unprivileged attacker entering through the VC revoke/spend/proof action in `RenderProperty` (packages/gui/src/components/vcs/VCCard.tsx) control DID identifier with alternate format or stale wallet mapping with conflicting localStorage preferences and drive the sequence connect -> approve -> switch context -> execute so the GUI would persist a malicious mirror/subscription that later drives unsafe content or wallet action, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCCard.tsx` / `RenderProperty`
- Entrypoint: VC revoke/spend/proof action
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with conflicting localStorage preferences
- Exploit idea: persist a malicious mirror/subscription that later drives unsafe content or wallet action
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

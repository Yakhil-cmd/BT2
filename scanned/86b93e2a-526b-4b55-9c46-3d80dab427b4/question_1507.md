# Q1507: did-vc-datalayer via didWallets 1507

## Question
Can an unprivileged attacker entering through the DID profile dropdown/change flow in `didWallets` (packages/gui/src/components/did/DIDProfileDropdown.tsx) control DataLayer offer summary with conflicting store IDs with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would apply a DID/VC/DataLayer action to a different wallet or store than displayed, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/did/DIDProfileDropdown.tsx` / `didWallets`
- Entrypoint: DID profile dropdown/change flow
- Attacker controls: DataLayer offer summary with conflicting store IDs; with a redirected remote resource
- Exploit idea: apply a DID/VC/DataLayer action to a different wallet or store than displayed
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

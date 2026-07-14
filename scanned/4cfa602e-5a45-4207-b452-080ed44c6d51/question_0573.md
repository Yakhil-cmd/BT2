# Q573: did-vc-datalayer via DIDProfileDropdown 573

## Question
Can an unprivileged attacker entering through the VC revoke/spend/proof action in `DIDProfileDropdown` (packages/gui/src/components/did/DIDProfileDropdown.tsx) control batch update keys and values with duplicated encodings with conflicting localStorage preferences and drive the sequence connect -> approve -> switch context -> execute so the GUI would submit a batch update whose displayed keys differ from RPC payload keys, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/did/DIDProfileDropdown.tsx` / `DIDProfileDropdown`
- Entrypoint: VC revoke/spend/proof action
- Attacker controls: batch update keys and values with duplicated encodings; with conflicting localStorage preferences
- Exploit idea: submit a batch update whose displayed keys differ from RPC payload keys
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

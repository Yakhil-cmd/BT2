# Q3698: did-vc-datalayer via VCs 3698

## Question
Can an unprivileged attacker entering through the VC revoke/spend/proof action in `VCs` (packages/gui/src/components/vcs/VCs.tsx) control DID identifier with alternate format or stale wallet mapping with precision-boundary values and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would submit a batch update whose displayed keys differ from RPC payload keys, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCs.tsx` / `VCs`
- Entrypoint: VC revoke/spend/proof action
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with precision-boundary values
- Exploit idea: submit a batch update whose displayed keys differ from RPC payload keys
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

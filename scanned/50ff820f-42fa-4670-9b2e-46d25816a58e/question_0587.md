# Q587: did-vc-datalayer via SigningEntityDID 587

## Question
Can an unprivileged attacker entering through the DID profile dropdown/change flow in `SigningEntityDID` (packages/gui/src/components/signVerify/SigningEntityDID.tsx) control VC proof/revoke payload from notification or RPC state with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would accept or revoke based on spoofed proof/store state, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityDID.tsx` / `SigningEntityDID`
- Entrypoint: DID profile dropdown/change flow
- Attacker controls: VC proof/revoke payload from notification or RPC state; with a stale Redux cache
- Exploit idea: accept or revoke based on spoofed proof/store state
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

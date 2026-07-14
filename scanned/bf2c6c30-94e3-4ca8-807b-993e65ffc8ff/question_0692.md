# Q692: did-vc-datalayer via didToDIDId 692

## Question
Can an unprivileged attacker entering through the DID profile dropdown/change flow in `didToDIDId` (packages/gui/src/util/dids.ts) control DID identifier with alternate format or stale wallet mapping after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mix DataLayer offer summary with normal offer acceptance path, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/util/dids.ts` / `didToDIDId`
- Entrypoint: DID profile dropdown/change flow
- Attacker controls: DID identifier with alternate format or stale wallet mapping; after canceling and reopening the dialog
- Exploit idea: mix DataLayer offer summary with normal offer acceptance path
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

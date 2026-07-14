# Q2560: did-vc-datalayer via didToDIDId 2560

## Question
Can an unprivileged attacker entering through the DataLayer store key update in `didToDIDId` (packages/gui/src/util/dids.ts) control batch update keys and values with duplicated encodings with a delayed metadata fetch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would apply a DID/VC/DataLayer action to a different wallet or store than displayed, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/util/dids.ts` / `didToDIDId`
- Entrypoint: DataLayer store key update
- Attacker controls: batch update keys and values with duplicated encodings; with a delayed metadata fetch
- Exploit idea: apply a DID/VC/DataLayer action to a different wallet or store than displayed
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

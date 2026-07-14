# Q2441: did-vc-datalayer via did 2441

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `did` (packages/gui/src/components/did/DIDProfileDropdown.tsx) control VC proof/revoke payload from notification or RPC state during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mix DataLayer offer summary with normal offer acceptance path, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/did/DIDProfileDropdown.tsx` / `did`
- Entrypoint: mirror/subscription action
- Attacker controls: VC proof/revoke payload from notification or RPC state; during a pending modal confirmation
- Exploit idea: mix DataLayer offer summary with normal offer acceptance path
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

# Q2760: did-vc-datalayer via handleCancel 2760

## Question
Can an unprivileged attacker entering through the VC revoke/spend/proof action in `handleCancel` (packages/gui/src/components/vcs/VCEditTitle.tsx) control VC proof/revoke payload from notification or RPC state with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would submit a batch update whose displayed keys differ from RPC payload keys, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCEditTitle.tsx` / `handleCancel`
- Entrypoint: VC revoke/spend/proof action
- Attacker controls: VC proof/revoke payload from notification or RPC state; with case-normalized identifiers
- Exploit idea: submit a batch update whose displayed keys differ from RPC payload keys
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

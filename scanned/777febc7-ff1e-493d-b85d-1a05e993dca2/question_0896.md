# Q896: did-vc-datalayer via VCs 896

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `VCs` (packages/gui/src/components/vcs/VCs.tsx) control VC proof/revoke payload from notification or RPC state with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would submit a batch update whose displayed keys differ from RPC payload keys, violating the invariant that DataLayer and normal wallet offers must not share unsafe acceptance assumptions, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCs.tsx` / `VCs`
- Entrypoint: mirror/subscription action
- Attacker controls: VC proof/revoke payload from notification or RPC state; with hidden Unicode characters
- Exploit idea: submit a batch update whose displayed keys differ from RPC payload keys
- Invariant to test: DataLayer and normal wallet offers must not share unsafe acceptance assumptions
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

# Q2371: address-notification via useWalletKeyAddresses 2371

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `useWalletKeyAddresses` (packages/gui/src/hooks/useWalletKeyAddresses.ts) control notification payload referencing offer/NFT/VC IDs with a duplicate identifier and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useWalletKeyAddresses.ts` / `useWalletKeyAddresses`
- Entrypoint: announcement link/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a duplicate identifier
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

# Q2370: address-notification via useWalletKeyAddresses 2370

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `useWalletKeyAddresses` (packages/gui/src/hooks/useWalletKeyAddresses.ts) control contact names and addresses with hidden characters with a duplicate identifier and drive the sequence fetch -> cache -> refresh -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useWalletKeyAddresses.ts` / `useWalletKeyAddresses`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; with a duplicate identifier
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

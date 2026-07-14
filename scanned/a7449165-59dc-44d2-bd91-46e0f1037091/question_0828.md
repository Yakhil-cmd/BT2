# Q828: address-notification via NotificationsContext 828

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `NotificationsContext` (packages/gui/src/components/notification/NotificationsProvider.tsx) control contact names and addresses with hidden characters after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsProvider.tsx` / `NotificationsContext`
- Entrypoint: burn/payout address helper
- Attacker controls: contact names and addresses with hidden characters; after a failed RPC response
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

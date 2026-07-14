# Q3622: address-notification via if 3622

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `if` (packages/gui/src/components/notification/Notification.tsx) control burn or payout address returned from helper state after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/Notification.tsx` / `if`
- Entrypoint: burn/payout address helper
- Attacker controls: burn or payout address returned from helper state; after a network switch
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

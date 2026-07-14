# Q3628: address-notification via NotificationsDropdown 3628

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `NotificationsDropdown` (packages/gui/src/components/notification/NotificationsDropdown.tsx) control contact names and addresses with hidden characters after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsDropdown.tsx` / `NotificationsDropdown`
- Entrypoint: burn/payout address helper
- Attacker controls: contact names and addresses with hidden characters; after canceling and reopening the dialog
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

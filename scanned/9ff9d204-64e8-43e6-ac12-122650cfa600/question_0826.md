# Q826: address-notification via buttonStyle 826

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `buttonStyle` (packages/gui/src/components/notification/NotificationsDropdown.tsx) control notification payload referencing offer/NFT/VC IDs after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsDropdown.tsx` / `buttonStyle`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; after a failed RPC response
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

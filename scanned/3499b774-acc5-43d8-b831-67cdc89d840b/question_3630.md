# Q3630: address-notification via triggeredNotificationsByCurrentFingerprint 3630

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `triggeredNotificationsByCurrentFingerprint` (packages/gui/src/components/notification/NotificationsProvider.tsx) control notification payload referencing offer/NFT/VC IDs after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsProvider.tsx` / `triggeredNotificationsByCurrentFingerprint`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; after canceling and reopening the dialog
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

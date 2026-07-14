# Q2696: address-notification via showNotification 2696

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `showNotification` (packages/gui/src/components/notification/NotificationsProvider.tsx) control burn or payout address returned from helper state with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsProvider.tsx` / `showNotification`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; with precision-boundary values
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

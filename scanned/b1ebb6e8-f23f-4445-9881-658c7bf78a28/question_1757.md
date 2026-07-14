# Q1757: address-notification via NotificationPreview 1757

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `NotificationPreview` (packages/gui/src/components/notification/NotificationPreview.tsx) control burn or payout address returned from helper state with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreview.tsx` / `NotificationPreview`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: burn or payout address returned from helper state; with a cached permission entry
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

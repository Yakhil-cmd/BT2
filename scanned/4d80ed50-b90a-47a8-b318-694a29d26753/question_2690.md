# Q2690: address-notification via handleURLClick 2690

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `handleURLClick` (packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx) control contact names and addresses with hidden characters with a cached permission entry and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx` / `handleURLClick`
- Entrypoint: contact selection in send forms
- Attacker controls: contact names and addresses with hidden characters; with a cached permission entry
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

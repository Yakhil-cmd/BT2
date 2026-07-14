# Q1759: address-notification via NotificationWrapper 1759

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `NotificationWrapper` (packages/gui/src/components/notification/NotificationWrapper.tsx) control contact names and addresses with hidden characters with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationWrapper.tsx` / `NotificationWrapper`
- Entrypoint: announcement link/action flow
- Attacker controls: contact names and addresses with hidden characters; with a cached permission entry
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

# Q424: address-notification via AddressBookAPI 424

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `AddressBookAPI` (packages/gui/src/electron/constants/AddressBookAPI.ts) control contact names and addresses with hidden characters after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/AddressBookAPI.ts` / `AddressBookAPI`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; after canceling and reopening the dialog
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

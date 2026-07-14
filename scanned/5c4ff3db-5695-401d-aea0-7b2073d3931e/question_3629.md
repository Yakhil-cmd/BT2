# Q3629: address-notification via NotificationsMenu 3629

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `NotificationsMenu` (packages/gui/src/components/notification/NotificationsMenu.tsx) control notification payload referencing offer/NFT/VC IDs with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsMenu.tsx` / `NotificationsMenu`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with precision-boundary values
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

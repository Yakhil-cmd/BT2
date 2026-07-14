# Q2693: address-notification via NotificationWrapper 2693

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `NotificationWrapper` (packages/gui/src/components/notification/NotificationWrapper.tsx) control notification payload referencing offer/NFT/VC IDs with reordered RPC events and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationWrapper.tsx` / `NotificationWrapper`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with reordered RPC events
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

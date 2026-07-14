# Q3305: address-notification via addresses 3305

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `addresses` (packages/gui/src/hooks/useWalletKeyAddresses.ts) control contact names and addresses with hidden characters after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useWalletKeyAddresses.ts` / `addresses`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; after canceling and reopening the dialog
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

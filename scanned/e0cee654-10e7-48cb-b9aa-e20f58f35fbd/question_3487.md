# Q3487: address-notification via handleShowNotification 3487

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `handleShowNotification` (packages/gui/src/hooks/useShowNotification.ts) control burn or payout address returned from helper state with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useShowNotification.ts` / `handleShowNotification`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; with case-normalized identifiers
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

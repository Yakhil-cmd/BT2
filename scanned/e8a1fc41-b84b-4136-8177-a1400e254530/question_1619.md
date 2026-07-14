# Q1619: address-notification via handleShowNotification 1619

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `handleShowNotification` (packages/gui/src/hooks/useShowNotification.ts) control notification payload referencing offer/NFT/VC IDs with a stale Redux cache and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useShowNotification.ts` / `handleShowNotification`
- Entrypoint: burn/payout address helper
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a stale Redux cache
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

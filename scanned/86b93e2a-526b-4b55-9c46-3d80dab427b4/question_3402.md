# Q3402: address-notification via getNewContactId 3402

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `getNewContactId` (packages/core/src/hooks/useAddressBook.tsx) control stale contact after edit/delete with a cached permission entry and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/hooks/useAddressBook.tsx` / `getNewContactId`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; with a cached permission entry
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

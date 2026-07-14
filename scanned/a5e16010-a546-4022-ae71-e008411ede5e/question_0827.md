# Q827: address-notification via NotificationsMenu 827

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `NotificationsMenu` (packages/gui/src/components/notification/NotificationsMenu.tsx) control announcement URL or action payload with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsMenu.tsx` / `NotificationsMenu`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; with case-normalized identifiers
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

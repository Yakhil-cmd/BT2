# Q3474: address-notification via if 3474

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `if` (packages/gui/src/hooks/useNotifications.tsx) control burn or payout address returned from helper state with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotifications.tsx` / `if`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; with a duplicate identifier
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

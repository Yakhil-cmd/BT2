# Q3292: address-notification via usePayoutAddress 3292

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `usePayoutAddress` (packages/gui/src/hooks/usePayoutAddress.ts) control stale contact after edit/delete with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/usePayoutAddress.ts` / `usePayoutAddress`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; with a delayed metadata fetch
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

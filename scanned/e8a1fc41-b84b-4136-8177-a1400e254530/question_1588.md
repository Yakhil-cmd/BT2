# Q1588: address-notification via prepareNotifications 1588

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `prepareNotifications` (packages/gui/src/hooks/useBlockchainNotifications.tsx) control burn or payout address returned from helper state with a delayed metadata fetch and drive the sequence connect -> approve -> switch context -> execute so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBlockchainNotifications.tsx` / `prepareNotifications`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: burn or payout address returned from helper state; with a delayed metadata fetch
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

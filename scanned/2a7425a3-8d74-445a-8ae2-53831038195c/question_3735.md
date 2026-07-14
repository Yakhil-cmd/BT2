# Q3735: address-notification via showAddresses 3735

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `showAddresses` (packages/gui/src/components/addressbook/MyContact.tsx) control announcement URL or action payload with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/MyContact.tsx` / `showAddresses`
- Entrypoint: announcement link/action flow
- Attacker controls: announcement URL or action payload; with hidden Unicode characters
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

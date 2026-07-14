# Q1772: address-notification via value 1772

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `value` (packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx) control contact names and addresses with hidden characters with case-normalized identifiers and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx` / `value`
- Entrypoint: burn/payout address helper
- Attacker controls: contact names and addresses with hidden characters; with case-normalized identifiers
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

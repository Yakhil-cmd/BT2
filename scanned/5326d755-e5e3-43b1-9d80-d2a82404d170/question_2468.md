# Q2468: address-notification via getAddressBook 2468

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `getAddressBook` (packages/core/src/hooks/useAddressBook.tsx) control notification payload referencing offer/NFT/VC IDs with conflicting localStorage preferences and drive the sequence fetch -> cache -> refresh -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/hooks/useAddressBook.tsx` / `getAddressBook`
- Entrypoint: contact selection in send forms
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with conflicting localStorage preferences
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

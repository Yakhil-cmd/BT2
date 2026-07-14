# Q325: address-notification via AddressBookAutocomplete 325

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `AddressBookAutocomplete` (packages/wallets/src/components/AddressBookAutocomplete.tsx) control notification payload referencing offer/NFT/VC IDs with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/AddressBookAutocomplete.tsx` / `AddressBookAutocomplete`
- Entrypoint: burn/payout address helper
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with hidden Unicode characters
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

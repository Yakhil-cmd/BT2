# Q818: address-notification via AddressBookMenuItem 818

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `AddressBookMenuItem` (packages/gui/src/components/addressbook/AddressBookMenuItem.tsx) control notification payload referencing offer/NFT/VC IDs with case-normalized identifiers and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBookMenuItem.tsx` / `AddressBookMenuItem`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with case-normalized identifiers
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

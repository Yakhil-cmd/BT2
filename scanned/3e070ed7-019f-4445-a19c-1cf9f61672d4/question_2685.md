# Q2685: address-notification via AddressBook 2685

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `AddressBook` (packages/gui/src/components/addressbook/AddressBook.tsx) control contact names and addresses with hidden characters after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBook.tsx` / `AddressBook`
- Entrypoint: contact selection in send forms
- Attacker controls: contact names and addresses with hidden characters; after canceling and reopening the dialog
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

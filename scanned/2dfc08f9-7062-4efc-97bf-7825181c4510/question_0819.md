# Q819: address-notification via AddressBookSideBar 819

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `AddressBookSideBar` (packages/gui/src/components/addressbook/AddressBookSideBar.tsx) control contact names and addresses with hidden characters with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBookSideBar.tsx` / `AddressBookSideBar`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: contact names and addresses with hidden characters; with hidden Unicode characters
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

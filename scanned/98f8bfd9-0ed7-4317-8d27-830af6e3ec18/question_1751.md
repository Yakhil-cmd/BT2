# Q1751: address-notification via AddressBook 1751

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `AddressBook` (packages/gui/src/components/addressbook/AddressBook.tsx) control burn or payout address returned from helper state with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/AddressBook.tsx` / `AddressBook`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: burn or payout address returned from helper state; with a duplicate identifier
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

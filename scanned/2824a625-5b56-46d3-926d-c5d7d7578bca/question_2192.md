# Q2192: address-notification via updatedValue 2192

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `updatedValue` (packages/wallets/src/components/AddressBookAutocomplete.tsx) control announcement URL or action payload after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/AddressBookAutocomplete.tsx` / `updatedValue`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: announcement URL or action payload; after a network switch
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

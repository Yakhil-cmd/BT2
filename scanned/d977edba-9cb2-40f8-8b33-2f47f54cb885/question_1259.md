# Q1259: address-notification via handleChange 1259

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `handleChange` (packages/wallets/src/components/AddressBookAutocomplete.tsx) control notification payload referencing offer/NFT/VC IDs after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/AddressBookAutocomplete.tsx` / `handleChange`
- Entrypoint: announcement link/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; after a failed RPC response
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

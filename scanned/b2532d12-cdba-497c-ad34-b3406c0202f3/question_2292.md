# Q2292: address-notification via AddressBookAPI 2292

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `AddressBookAPI` (packages/gui/src/electron/constants/AddressBookAPI.ts) control announcement URL or action payload with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/AddressBookAPI.ts` / `AddressBookAPI`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; with a delayed metadata fetch
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

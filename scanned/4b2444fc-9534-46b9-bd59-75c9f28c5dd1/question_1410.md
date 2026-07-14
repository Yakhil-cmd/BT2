# Q1410: address-notification via if 1410

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `if` (packages/gui/src/electron/utils/showNotification.ts) control notification payload referencing offer/NFT/VC IDs during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/showNotification.ts` / `if`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; during a pending modal confirmation
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

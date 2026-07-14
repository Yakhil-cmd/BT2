# Q600: address-notification via useAddressBook 600

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `useAddressBook` (packages/core/src/hooks/useAddressBook.tsx) control stale contact after edit/delete with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/hooks/useAddressBook.tsx` / `useAddressBook`
- Entrypoint: notification preview/action flow
- Attacker controls: stale contact after edit/delete; with a stale Redux cache
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

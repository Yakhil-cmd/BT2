# Q2795: address-notification via index 2795

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `index` (packages/core/src/components/AddressBookProvider/index.ts) control notification payload referencing offer/NFT/VC IDs with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would select a contact that displays one address while submitting another, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/components/AddressBookProvider/index.ts` / `index`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with precision-boundary values
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

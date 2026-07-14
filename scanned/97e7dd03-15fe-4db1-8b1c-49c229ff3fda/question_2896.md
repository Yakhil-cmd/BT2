# Q2896: address-notification via handleNewAddress 2896

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `handleNewAddress` (packages/wallets/src/components/WalletReceiveAddress.tsx) control notification payload referencing offer/NFT/VC IDs with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletReceiveAddress.tsx` / `handleNewAddress`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a cached permission entry
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

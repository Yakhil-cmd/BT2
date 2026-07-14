# Q3831: address-notification via WalletReceiveAddress 3831

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `WalletReceiveAddress` (packages/wallets/src/components/WalletReceiveAddress.tsx) control notification payload referencing offer/NFT/VC IDs with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletReceiveAddress.tsx` / `WalletReceiveAddress`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with reordered RPC events
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

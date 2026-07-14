# Q95: address-notification via WalletReceiveAddress 95

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `WalletReceiveAddress` (packages/wallets/src/components/WalletReceiveAddress.tsx) control notification payload referencing offer/NFT/VC IDs with a stale Redux cache and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletReceiveAddress.tsx` / `WalletReceiveAddress`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a stale Redux cache
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

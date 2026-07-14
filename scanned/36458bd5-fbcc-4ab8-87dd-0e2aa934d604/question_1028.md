# Q1028: address-notification via handleNewAddress 1028

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `handleNewAddress` (packages/wallets/src/components/WalletReceiveAddress.tsx) control stale contact after edit/delete with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletReceiveAddress.tsx` / `handleNewAddress`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; with a delayed metadata fetch
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

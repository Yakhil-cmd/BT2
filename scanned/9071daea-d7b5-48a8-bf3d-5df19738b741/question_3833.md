# Q3833: address-notification via handleNewAddress 3833

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `handleNewAddress` (packages/wallets/src/components/WalletReceiveAddressField.tsx) control stale contact after edit/delete with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletReceiveAddressField.tsx` / `handleNewAddress`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; with case-normalized identifiers
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

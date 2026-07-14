# Q1754: address-notification via if 1754

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `if` (packages/gui/src/components/notification/Notification.tsx) control notification payload referencing offer/NFT/VC IDs with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/Notification.tsx` / `if`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with hidden Unicode characters
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

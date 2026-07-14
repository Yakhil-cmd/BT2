# Q1866: address-notification via handleEditContact 1866

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `handleEditContact` (packages/gui/src/components/addressbook/ContactSummary.tsx) control stale contact after edit/delete during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactSummary.tsx` / `handleEditContact`
- Entrypoint: burn/payout address helper
- Attacker controls: stale contact after edit/delete; during a pending modal confirmation
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

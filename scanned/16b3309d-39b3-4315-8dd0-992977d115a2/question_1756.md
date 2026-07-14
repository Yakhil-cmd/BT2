# Q1756: address-notification via handleClose 1756

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `handleClose` (packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx) control notification payload referencing offer/NFT/VC IDs with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx` / `handleClose`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with conflicting localStorage preferences
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

# Q1755: address-notification via if 1755

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `if` (packages/gui/src/components/notification/NotificationAnnouncement.tsx) control notification payload referencing offer/NFT/VC IDs with reordered RPC events and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncement.tsx` / `if`
- Entrypoint: burn/payout address helper
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with reordered RPC events
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

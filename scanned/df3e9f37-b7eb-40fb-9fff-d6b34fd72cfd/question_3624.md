# Q3624: address-notification via urlLabel 3624

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `urlLabel` (packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx) control contact names and addresses with hidden characters with reordered RPC events and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx` / `urlLabel`
- Entrypoint: burn/payout address helper
- Attacker controls: contact names and addresses with hidden characters; with reordered RPC events
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

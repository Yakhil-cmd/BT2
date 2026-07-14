# Q580: address-notification via NotificationPreviewOffer 580

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `NotificationPreviewOffer` (packages/gui/src/components/notification/NotificationPreviewOffer.tsx) control announcement URL or action payload with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewOffer.tsx` / `NotificationPreviewOffer`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; with case-normalized identifiers
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

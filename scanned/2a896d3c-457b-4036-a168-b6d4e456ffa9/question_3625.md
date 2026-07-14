# Q3625: address-notification via NotificationPreview 3625

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `NotificationPreview` (packages/gui/src/components/notification/NotificationPreview.tsx) control announcement URL or action payload with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreview.tsx` / `NotificationPreview`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; with case-normalized identifiers
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

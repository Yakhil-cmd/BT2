# Q1762: address-notification via NotificationsProvider 1762

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `NotificationsProvider` (packages/gui/src/components/notification/NotificationsProvider.tsx) control stale contact after edit/delete after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsProvider.tsx` / `NotificationsProvider`
- Entrypoint: announcement link/action flow
- Attacker controls: stale contact after edit/delete; after a network switch
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

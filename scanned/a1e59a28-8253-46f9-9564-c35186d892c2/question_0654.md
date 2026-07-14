# Q654: address-notification via useBlockchainNotifications 654

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `useBlockchainNotifications` (packages/gui/src/hooks/useBlockchainNotifications.tsx) control stale contact after edit/delete with a stale Redux cache and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBlockchainNotifications.tsx` / `useBlockchainNotifications`
- Entrypoint: notification preview/action flow
- Attacker controls: stale contact after edit/delete; with a stale Redux cache
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

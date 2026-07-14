# Q1411: address-notification via if 1411

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `if` (packages/gui/src/electron/utils/showNotification.ts) control announcement URL or action payload during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/showNotification.ts` / `if`
- Entrypoint: notification preview/action flow
- Attacker controls: announcement URL or action payload; during a pending modal confirmation
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

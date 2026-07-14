# Q3473: address-notification via useNotificationSettings 3473

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `useNotificationSettings` (packages/gui/src/hooks/useNotificationSettings.ts) control contact names and addresses with hidden characters through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotificationSettings.ts` / `useNotificationSettings`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; through a batch of rapid user-accessible actions
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

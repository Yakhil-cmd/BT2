# Q3490: address-notification via unseenCount 3490

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `unseenCount` (packages/gui/src/hooks/useValidNotifications.ts) control burn or payout address returned from helper state through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useValidNotifications.ts` / `unseenCount`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; through a batch of rapid user-accessible actions
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

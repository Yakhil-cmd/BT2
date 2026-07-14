# Q476: address-notification via createNotificationPayload 476

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `createNotificationPayload` (packages/gui/src/electron/utils/showNotification.ts) control stale contact after edit/delete with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/showNotification.ts` / `createNotificationPayload`
- Entrypoint: notification preview/action flow
- Attacker controls: stale contact after edit/delete; with a redirected remote resource
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

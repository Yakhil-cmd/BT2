# Q3278: address-notification via createNotificationPayload 3278

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `createNotificationPayload` (packages/gui/src/electron/utils/showNotification.ts) control announcement URL or action payload through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/showNotification.ts` / `createNotificationPayload`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; through a batch of rapid user-accessible actions
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

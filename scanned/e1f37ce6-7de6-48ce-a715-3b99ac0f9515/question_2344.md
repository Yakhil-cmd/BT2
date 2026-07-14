# Q2344: address-notification via showNotification 2344

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `showNotification` (packages/gui/src/electron/utils/showNotification.ts) control announcement URL or action payload with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/showNotification.ts` / `showNotification`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; with hidden Unicode characters
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

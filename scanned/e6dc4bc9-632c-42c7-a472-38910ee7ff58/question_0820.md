# Q820: address-notification via Notification 820

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `Notification` (packages/gui/src/components/notification/Notification.tsx) control contact names and addresses with hidden characters during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/Notification.tsx` / `Notification`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; during a pending modal confirmation
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

# Q821: address-notification via NotificationAnnouncement 821

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `NotificationAnnouncement` (packages/gui/src/components/notification/NotificationAnnouncement.tsx) control announcement URL or action payload with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncement.tsx` / `NotificationAnnouncement`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; with a cached permission entry
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

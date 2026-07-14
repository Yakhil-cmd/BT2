# Q3623: address-notification via NotificationAnnouncement 3623

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `NotificationAnnouncement` (packages/gui/src/components/notification/NotificationAnnouncement.tsx) control notification payload referencing offer/NFT/VC IDs with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationAnnouncement.tsx` / `NotificationAnnouncement`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a redirected remote resource
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

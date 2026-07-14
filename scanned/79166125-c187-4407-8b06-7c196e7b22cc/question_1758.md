# Q1758: address-notification via allowCounterOffer 1758

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `allowCounterOffer` (packages/gui/src/components/notification/NotificationSendDialog.tsx) control announcement URL or action payload after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationSendDialog.tsx` / `allowCounterOffer`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; after a network switch
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

# Q2448: address-notification via if 2448

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `if` (packages/gui/src/components/notification/NotificationPreviewOffer.tsx) control announcement URL or action payload during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewOffer.tsx` / `if`
- Entrypoint: notification preview/action flow
- Attacker controls: announcement URL or action payload; during a pending modal confirmation
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

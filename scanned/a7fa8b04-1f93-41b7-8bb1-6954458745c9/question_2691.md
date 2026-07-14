# Q2691: address-notification via NotificationPreview 2691

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `NotificationPreview` (packages/gui/src/components/notification/NotificationPreview.tsx) control contact names and addresses with hidden characters with reordered RPC events and drive the sequence open notification -> resolve details -> execute so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreview.tsx` / `NotificationPreview`
- Entrypoint: contact selection in send forms
- Attacker controls: contact names and addresses with hidden characters; with reordered RPC events
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

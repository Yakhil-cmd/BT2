# Q685: address-notification via useShowNotification 685

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `useShowNotification` (packages/gui/src/hooks/useShowNotification.ts) control announcement URL or action payload after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useShowNotification.ts` / `useShowNotification`
- Entrypoint: contact selection in send forms
- Attacker controls: announcement URL or action payload; after canceling and reopening the dialog
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

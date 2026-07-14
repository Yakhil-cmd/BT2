# Q671: address-notification via useNotificationSettings 671

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `useNotificationSettings` (packages/gui/src/hooks/useNotificationSettings.ts) control notification payload referencing offer/NFT/VC IDs after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotificationSettings.ts` / `useNotificationSettings`
- Entrypoint: contact selection in send forms
- Attacker controls: notification payload referencing offer/NFT/VC IDs; after a failed RPC response
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

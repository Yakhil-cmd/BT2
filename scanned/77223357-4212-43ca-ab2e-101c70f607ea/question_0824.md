# Q824: address-notification via NotificationSendDialog 824

## Question
Can an unprivileged attacker entering through the address book add/edit/autocomplete flow in `NotificationSendDialog` (packages/gui/src/components/notification/NotificationSendDialog.tsx) control notification payload referencing offer/NFT/VC IDs after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationSendDialog.tsx` / `NotificationSendDialog`
- Entrypoint: address book add/edit/autocomplete flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; after a failed RPC response
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

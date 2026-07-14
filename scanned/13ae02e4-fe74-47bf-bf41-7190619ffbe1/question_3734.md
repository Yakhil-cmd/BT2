# Q3734: address-notification via getImage 3734

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `getImage` (packages/gui/src/components/addressbook/ContactSummary.tsx) control announcement URL or action payload after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactSummary.tsx` / `getImage`
- Entrypoint: notification preview/action flow
- Attacker controls: announcement URL or action payload; after a failed RPC response
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

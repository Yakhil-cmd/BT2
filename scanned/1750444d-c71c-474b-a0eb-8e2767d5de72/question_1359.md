# Q1359: address-notification via AddressBookAPI 1359

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `AddressBookAPI` (packages/gui/src/electron/constants/AddressBookAPI.ts) control notification payload referencing offer/NFT/VC IDs with a stale Redux cache and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/AddressBookAPI.ts` / `AddressBookAPI`
- Entrypoint: notification preview/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a stale Redux cache
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

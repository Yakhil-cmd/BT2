# Q1761: address-notification via handleSeeAllActivity 1761

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `handleSeeAllActivity` (packages/gui/src/components/notification/NotificationsMenu.tsx) control notification payload referencing offer/NFT/VC IDs with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/notification/NotificationsMenu.tsx` / `handleSeeAllActivity`
- Entrypoint: announcement link/action flow
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a redirected remote resource
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

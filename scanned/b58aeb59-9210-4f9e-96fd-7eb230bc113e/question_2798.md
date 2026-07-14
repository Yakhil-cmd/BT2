# Q2798: address-notification via handleRemove 2798

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `handleRemove` (packages/gui/src/components/addressbook/ContactAdd.tsx) control burn or payout address returned from helper state with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/addressbook/ContactAdd.tsx` / `handleRemove`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; with reordered RPC events
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

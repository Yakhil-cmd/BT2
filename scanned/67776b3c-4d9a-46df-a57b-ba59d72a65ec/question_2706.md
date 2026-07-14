# Q2706: address-notification via AddressBookProvider 2706

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `AddressBookProvider` (packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx) control contact names and addresses with hidden characters after a failed RPC response and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx` / `AddressBookProvider`
- Entrypoint: announcement link/action flow
- Attacker controls: contact names and addresses with hidden characters; after a failed RPC response
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

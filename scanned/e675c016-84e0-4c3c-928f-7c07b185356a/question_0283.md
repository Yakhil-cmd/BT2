# Q283: address-notification via SigningEntityWalletAddress 283

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `SigningEntityWalletAddress` (packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx) control contact names and addresses with hidden characters with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would select a contact that displays one address while submitting another, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx` / `SigningEntityWalletAddress`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; with a redirected remote resource
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

# Q688: address-notification via getOfferId 688

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `getOfferId` (packages/gui/src/hooks/useValidNotifications.ts) control burn or payout address returned from helper state after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useValidNotifications.ts` / `getOfferId`
- Entrypoint: contact selection in send forms
- Attacker controls: burn or payout address returned from helper state; after a failed RPC response
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

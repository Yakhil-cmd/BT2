# Q3457: address-notification via retireAddress 3457

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `retireAddress` (packages/gui/src/hooks/useBurnAddress.ts) control contact names and addresses with hidden characters after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBurnAddress.ts` / `retireAddress`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; after a network switch
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

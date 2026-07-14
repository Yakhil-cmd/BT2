# Q1622: address-notification via filterNotifications 1622

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `filterNotifications` (packages/gui/src/hooks/useValidNotifications.ts) control burn or payout address returned from helper state after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an offer/NFT/VC action from a spoofed notification payload, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useValidNotifications.ts` / `filterNotifications`
- Entrypoint: burn/payout address helper
- Attacker controls: burn or payout address returned from helper state; after a network switch
- Exploit idea: trigger an offer/NFT/VC action from a spoofed notification payload
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

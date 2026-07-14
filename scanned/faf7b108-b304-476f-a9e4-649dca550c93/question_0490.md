# Q490: address-notification via usePayoutAddress 490

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `usePayoutAddress` (packages/gui/src/hooks/usePayoutAddress.ts) control burn or payout address returned from helper state with a duplicate identifier and drive the sequence fetch -> cache -> refresh -> submit so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/usePayoutAddress.ts` / `usePayoutAddress`
- Entrypoint: notification preview/action flow
- Attacker controls: burn or payout address returned from helper state; with a duplicate identifier
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

# Q1589: address-notification via retireAddress 1589

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `retireAddress` (packages/gui/src/hooks/useBurnAddress.ts) control announcement URL or action payload with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBurnAddress.ts` / `retireAddress`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; with hidden Unicode characters
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

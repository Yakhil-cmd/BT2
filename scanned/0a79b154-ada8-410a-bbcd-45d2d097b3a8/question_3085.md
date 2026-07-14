# Q3085: address-notification via SigningEntityWalletAddress 3085

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `SigningEntityWalletAddress` (packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx) control burn or payout address returned from helper state after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would select a contact that displays one address while submitting another, violating the invariant that address book changes must invalidate pending form state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx` / `SigningEntityWalletAddress`
- Entrypoint: burn/payout address helper
- Attacker controls: burn or payout address returned from helper state; after a failed RPC response
- Exploit idea: select a contact that displays one address while submitting another
- Invariant to test: address book changes must invalidate pending form state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

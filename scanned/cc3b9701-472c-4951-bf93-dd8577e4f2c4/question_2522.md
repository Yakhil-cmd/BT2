# Q2522: address-notification via items 2522

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `items` (packages/gui/src/hooks/useBlockchainNotifications.tsx) control contact names and addresses with hidden characters with conflicting localStorage preferences and drive the sequence load persisted state -> render approval -> execute command so the GUI would reuse a deleted/edited contact in a pending send form, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useBlockchainNotifications.tsx` / `items`
- Entrypoint: contact selection in send forms
- Attacker controls: contact names and addresses with hidden characters; with conflicting localStorage preferences
- Exploit idea: reuse a deleted/edited contact in a pending send form
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

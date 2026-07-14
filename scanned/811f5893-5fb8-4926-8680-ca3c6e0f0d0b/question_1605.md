# Q1605: address-notification via useNotificationSettings 1605

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `useNotificationSettings` (packages/gui/src/hooks/useNotificationSettings.ts) control announcement URL or action payload after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotificationSettings.ts` / `useNotificationSettings`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; after a network switch
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

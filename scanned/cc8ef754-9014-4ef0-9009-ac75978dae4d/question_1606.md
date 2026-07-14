# Q1606: address-notification via if 1606

## Question
Can an unprivileged attacker entering through the burn/payout address helper in `if` (packages/gui/src/hooks/useNotifications.tsx) control announcement URL or action payload through a batch of rapid user-accessible actions and drive the sequence open notification -> resolve details -> execute so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/hooks/useNotifications.tsx` / `if`
- Entrypoint: burn/payout address helper
- Attacker controls: announcement URL or action payload; through a batch of rapid user-accessible actions
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

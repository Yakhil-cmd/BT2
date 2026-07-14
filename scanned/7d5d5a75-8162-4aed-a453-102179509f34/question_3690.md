# Q3690: address-notification via SettingsNotifications 3690

## Question
Can an unprivileged attacker entering through the notification preview/action flow in `SettingsNotifications` (packages/gui/src/components/settings/SettingsNotifications.tsx) control contact names and addresses with hidden characters after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that notification-driven actions must revalidate ownership and current state, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNotifications.tsx` / `SettingsNotifications`
- Entrypoint: notification preview/action flow
- Attacker controls: contact names and addresses with hidden characters; after a failed RPC response
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: notification-driven actions must revalidate ownership and current state
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

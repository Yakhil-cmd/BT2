# Q2756: address-notification via SettingsNotifications 2756

## Question
Can an unprivileged attacker entering through the announcement link/action flow in `SettingsNotifications` (packages/gui/src/components/settings/SettingsNotifications.tsx) control burn or payout address returned from helper state with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would open an unsafe announcement link that can influence wallet approvals, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNotifications.tsx` / `SettingsNotifications`
- Entrypoint: announcement link/action flow
- Attacker controls: burn or payout address returned from helper state; with hidden Unicode characters
- Exploit idea: open an unsafe announcement link that can influence wallet approvals
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

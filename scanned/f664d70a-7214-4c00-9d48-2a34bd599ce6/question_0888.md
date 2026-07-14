# Q888: address-notification via SettingsNotifications 888

## Question
Can an unprivileged attacker entering through the contact selection in send forms in `SettingsNotifications` (packages/gui/src/components/settings/SettingsNotifications.tsx) control notification payload referencing offer/NFT/VC IDs with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would confuse burn address and recipient address in destructive asset flows, violating the invariant that displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows, leading to High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNotifications.tsx` / `SettingsNotifications`
- Entrypoint: contact selection in send forms
- Attacker controls: notification payload referencing offer/NFT/VC IDs; with a redirected remote resource
- Exploit idea: confuse burn address and recipient address in destructive asset flows
- Invariant to test: displayed contact/notification/action identity must equal the payload consumed by wallet-impacting flows
- Expected Immunefi impact: High: spoofed address/notification state causing wrong destination, wrong asset approval, or unsafe wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

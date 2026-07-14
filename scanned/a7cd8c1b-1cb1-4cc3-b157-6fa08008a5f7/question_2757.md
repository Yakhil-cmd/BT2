# Q2757: auth-profile via SettingsProfiles 2757

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `SettingsProfiles` (packages/gui/src/components/settings/SettingsProfiles.tsx) control private preference values migrated from localStorage during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SettingsProfiles.tsx` / `SettingsProfiles`
- Entrypoint: keyring migration prompt
- Attacker controls: private preference values migrated from localStorage; during a pending modal confirmation
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

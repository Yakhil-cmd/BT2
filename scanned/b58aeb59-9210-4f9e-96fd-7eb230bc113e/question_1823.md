# Q1823: auth-profile via didList 1823

## Question
Can an unprivileged attacker entering through the persisted preference reload in `didList` (packages/gui/src/components/settings/SettingsProfiles.tsx) control private preference values migrated from localStorage with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SettingsProfiles.tsx` / `didList`
- Entrypoint: persisted preference reload
- Attacker controls: private preference values migrated from localStorage; with a redirected remote resource
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

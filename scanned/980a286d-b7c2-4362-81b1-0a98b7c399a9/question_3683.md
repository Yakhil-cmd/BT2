# Q3683: auth-profile via handleKeyDown 3683

## Question
Can an unprivileged attacker entering through the persisted preference reload in `handleKeyDown` (packages/gui/src/components/settings/ProfileView.tsx) control rapid logout/login/profile switch timing after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ProfileView.tsx` / `handleKeyDown`
- Entrypoint: persisted preference reload
- Attacker controls: rapid logout/login/profile switch timing; after a network switch
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

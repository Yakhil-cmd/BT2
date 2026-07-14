# Q3568: auth-profile via KeyringStatus 3568

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `KeyringStatus` (packages/api/src/@types/KeyringStatus.ts) control prompt reason mismatch through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/@types/KeyringStatus.ts` / `KeyringStatus`
- Entrypoint: profile/fingerprint switch
- Attacker controls: prompt reason mismatch; through a batch of rapid user-accessible actions
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

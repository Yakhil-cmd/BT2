# Q3691: auth-profile via didList 3691

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `didList` (packages/gui/src/components/settings/SettingsProfiles.tsx) control prompt reason mismatch with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SettingsProfiles.tsx` / `didList`
- Entrypoint: profile/fingerprint switch
- Attacker controls: prompt reason mismatch; with hidden Unicode characters
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

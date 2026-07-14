# Q889: auth-profile via SettingsProfiles 889

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `SettingsProfiles` (packages/gui/src/components/settings/SettingsProfiles.tsx) control prompt reason mismatch with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would leave modal approval state alive across account changes, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SettingsProfiles.tsx` / `SettingsProfiles`
- Entrypoint: passphrase prompt workflow
- Attacker controls: prompt reason mismatch; with case-normalized identifiers
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

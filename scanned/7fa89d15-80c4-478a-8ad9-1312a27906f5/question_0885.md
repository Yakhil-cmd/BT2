# Q885: did-vc-datalayer via SettingsDataLayer 885

## Question
Can an unprivileged attacker entering through the DataLayer offer take/cancel flow in `SettingsDataLayer` (packages/gui/src/components/settings/SettingsDataLayer.tsx) control VC proof/revoke payload from notification or RPC state with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would persist a malicious mirror/subscription that later drives unsafe content or wallet action, violating the invariant that external mirror/subscription data must not bypass confirmation, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/settings/SettingsDataLayer.tsx` / `SettingsDataLayer`
- Entrypoint: DataLayer offer take/cancel flow
- Attacker controls: VC proof/revoke payload from notification or RPC state; with conflicting localStorage preferences
- Exploit idea: persist a malicious mirror/subscription that later drives unsafe content or wallet action
- Invariant to test: external mirror/subscription data must not bypass confirmation
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

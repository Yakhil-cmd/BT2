# Q3687: did-vc-datalayer via SettingsDataLayer 3687

## Question
Can an unprivileged attacker entering through the mirror/subscription action in `SettingsDataLayer` (packages/gui/src/components/settings/SettingsDataLayer.tsx) control DID identifier with alternate format or stale wallet mapping with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would apply a DID/VC/DataLayer action to a different wallet or store than displayed, violating the invariant that DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/settings/SettingsDataLayer.tsx` / `SettingsDataLayer`
- Entrypoint: mirror/subscription action
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with case-normalized identifiers
- Exploit idea: apply a DID/VC/DataLayer action to a different wallet or store than displayed
- Invariant to test: DID, VC, storeId, proof, key, and offer summary identity must remain canonical and wallet-bound from display through RPC submission
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

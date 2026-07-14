# Q2759: did-vc-datalayer via renderBackButton 2759

## Question
Can an unprivileged attacker entering through the DataLayer offer take/cancel flow in `renderBackButton` (packages/gui/src/components/vcs/VCDetail.tsx) control DID identifier with alternate format or stale wallet mapping with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would apply a DID/VC/DataLayer action to a different wallet or store than displayed, violating the invariant that external mirror/subscription data must not bypass confirmation, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCDetail.tsx` / `renderBackButton`
- Entrypoint: DataLayer offer take/cancel flow
- Attacker controls: DID identifier with alternate format or stale wallet mapping; with a duplicate identifier
- Exploit idea: apply a DID/VC/DataLayer action to a different wallet or store than displayed
- Invariant to test: external mirror/subscription data must not bypass confirmation
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

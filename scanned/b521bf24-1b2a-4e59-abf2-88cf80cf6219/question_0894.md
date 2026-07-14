# Q894: did-vc-datalayer via ItemContainer 894

## Question
Can an unprivileged attacker entering through the DID profile dropdown/change flow in `ItemContainer` (packages/gui/src/components/vcs/VCList.tsx) control DID identifier with alternate format or stale wallet mapping after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would apply a DID/VC/DataLayer action to a different wallet or store than displayed, violating the invariant that external mirror/subscription data must not bypass confirmation, leading to Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval?

## Target
- File/function: `packages/gui/src/components/vcs/VCList.tsx` / `ItemContainer`
- Entrypoint: DID profile dropdown/change flow
- Attacker controls: DID identifier with alternate format or stale wallet mapping; after canceling and reopening the dialog
- Exploit idea: apply a DID/VC/DataLayer action to a different wallet or store than displayed
- Invariant to test: external mirror/subscription data must not bypass confirmation
- Expected Immunefi impact: Critical: unauthorized DID/VC/DataLayer spend/revoke/offer action; High: spoofed identity/store state causing wrong approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

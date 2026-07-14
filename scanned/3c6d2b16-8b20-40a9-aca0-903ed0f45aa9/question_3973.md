# Q3973: offers via handleExpirationSubmit 3973

## Question
Can an unprivileged attacker entering through the crafted offer file import in `handleExpirationSubmit` (packages/gui/src/components/offers2/CreateOfferBuilder.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries during a pending modal confirmation and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/CreateOfferBuilder.tsx` / `handleExpirationSubmit`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; during a pending modal confirmation
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

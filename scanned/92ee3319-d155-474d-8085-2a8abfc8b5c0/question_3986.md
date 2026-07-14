# Q3986: offers via OfferBuilderHeader 3986

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderHeader` (packages/gui/src/components/offers2/OfferBuilderHeader.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderHeader.tsx` / `OfferBuilderHeader`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with reordered RPC events
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

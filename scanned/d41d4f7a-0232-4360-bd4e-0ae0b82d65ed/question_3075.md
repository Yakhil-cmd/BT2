# Q3075: offers via infos 3075

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `infos` (packages/gui/src/components/offers2/OfferDetails.tsx) control remote offer URL response that changes between preview and acceptance after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferDetails.tsx` / `infos`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; after canceling and reopening the dialog
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

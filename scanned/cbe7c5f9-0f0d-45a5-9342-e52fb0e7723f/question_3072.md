# Q3072: offers via handleRemove 3072

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `handleRemove` (packages/gui/src/components/offers2/OfferBuilderXCHSection.tsx) control offer bytes whose summary differs from displayed builder data with a delayed metadata fetch and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderXCHSection.tsx` / `handleRemove`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with a delayed metadata fetch
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

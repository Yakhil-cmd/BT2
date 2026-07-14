# Q990: offers via OfferBuilderWalletAmount 990

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderWalletAmount` (packages/gui/src/components/offers2/OfferBuilderWalletAmount.tsx) control conflicting offer IDs and secure-cancel flags with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderWalletAmount.tsx` / `OfferBuilderWalletAmount`
- Entrypoint: incoming offer notification open flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with case-normalized identifiers
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

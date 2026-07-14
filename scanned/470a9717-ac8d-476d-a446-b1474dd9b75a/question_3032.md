# Q3032: offers via OfferSummaryTokenRow 3032

## Question
Can an unprivileged attacker entering through the crafted offer file import in `OfferSummaryTokenRow` (packages/gui/src/components/offers/OfferSummaryRow.tsx) control offer bytes whose summary differs from displayed builder data with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummaryRow.tsx` / `OfferSummaryTokenRow`
- Entrypoint: crafted offer file import
- Attacker controls: offer bytes whose summary differs from displayed builder data; with case-normalized identifiers
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

# Q2837: offers via cardContentElem 2837

## Question
Can an unprivileged attacker entering through the crafted offer file import in `cardContentElem` (packages/gui/src/components/offers/NFTOfferPreview.tsx) control offer bytes whose summary differs from displayed builder data with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferPreview.tsx` / `cardContentElem`
- Entrypoint: crafted offer file import
- Attacker controls: offer bytes whose summary differs from displayed builder data; with precision-boundary values
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

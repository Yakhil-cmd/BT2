# Q3318: offers via extractCrCatData 3318

## Question
Can an unprivileged attacker entering through the crafted offer file import in `extractCrCatData` (packages/gui/src/util/offerToOfferBuilderData.ts) control NFT/CAT identifiers with duplicate or ambiguous entries after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/offerToOfferBuilderData.ts` / `extractCrCatData`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a failed RPC response
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

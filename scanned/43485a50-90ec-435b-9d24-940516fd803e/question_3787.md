# Q3787: offers via rows 3787

## Question
Can an unprivileged attacker entering through the crafted offer file import in `rows` (packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx` / `rows`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with hidden Unicode characters
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

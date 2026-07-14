# Q3786: offers via rows 3786

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `rows` (packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx) control offer bytes whose summary differs from displayed builder data with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx` / `rows`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with hidden Unicode characters
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

# Q2079: offers via onSubmit 2079

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `onSubmit` (packages/gui/src/components/offers/OfferEditor.tsx) control offer bytes whose summary differs from displayed builder data with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferEditor.tsx` / `onSubmit`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with a redirected remote resource
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

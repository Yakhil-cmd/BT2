# Q575: nft-metadata via FilterPill 575

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `FilterPill` (packages/gui/src/components/nfts/gallery/FilterPill.tsx) control content hash/status fields that change across fetches after canceling and reopening the dialog and drive the sequence select -> edit backing object -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/FilterPill.tsx` / `FilterPill`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; after canceling and reopening the dialog
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

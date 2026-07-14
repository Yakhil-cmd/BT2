# Q2401: nft-metadata via useNFTCoinRemoved 2401

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useNFTCoinRemoved` (packages/api-react/src/hooks/useNFTCoinRemoved.ts) control HTML/SVG/media content rendered in preview after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinRemoved.ts` / `useNFTCoinRemoved`
- Entrypoint: on-demand NFT data provider
- Attacker controls: HTML/SVG/media content rendered in preview; after canceling and reopening the dialog
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

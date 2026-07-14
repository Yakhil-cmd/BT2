# Q2018: nft-metadata via handleChange 2018

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `handleChange` (packages/gui/src/components/nfts/NFTAutocomplete.tsx) control objectionable-content flags and hidden NFT state after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTAutocomplete.tsx` / `handleChange`
- Entrypoint: on-demand NFT data provider
- Attacker controls: objectionable-content flags and hidden NFT state; after canceling and reopening the dialog
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

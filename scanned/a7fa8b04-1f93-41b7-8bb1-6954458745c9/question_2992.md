# Q2992: nft-metadata via context 2992

## Question
Can an unprivileged attacker entering through the external NFT link open action in `context` (packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx) control objectionable-content flags and hidden NFT state through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGalleryScrollPositionProvider.tsx` / `context`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; through a batch of rapid user-accessible actions
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

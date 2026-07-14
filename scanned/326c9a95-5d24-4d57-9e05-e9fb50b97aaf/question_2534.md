# Q2534: nft-metadata via useNFTImageFittingMode 2534

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTImageFittingMode` (packages/gui/src/hooks/useNFTImageFittingMode.tsx) control content hash/status fields that change across fetches with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTImageFittingMode.tsx` / `useNFTImageFittingMode`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; with precision-boundary values
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

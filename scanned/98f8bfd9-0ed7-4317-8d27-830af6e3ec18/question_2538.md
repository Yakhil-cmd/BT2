# Q2538: nft-metadata via useNachoNFTs 2538

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `useNachoNFTs` (packages/gui/src/hooks/useNachoNFTs.ts) control HTML/SVG/media content rendered in preview through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNachoNFTs.ts` / `useNachoNFTs`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; through a batch of rapid user-accessible actions
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

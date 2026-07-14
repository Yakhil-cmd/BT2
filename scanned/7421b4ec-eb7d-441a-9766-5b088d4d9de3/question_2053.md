# Q2053: nft-metadata via NFTDetailLoaded 2053

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTDetailLoaded` (packages/gui/src/components/nfts/detail/NFTDetailV2.tsx) control objectionable-content flags and hidden NFT state after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/detail/NFTDetailV2.tsx` / `NFTDetailLoaded`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; after a profile switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

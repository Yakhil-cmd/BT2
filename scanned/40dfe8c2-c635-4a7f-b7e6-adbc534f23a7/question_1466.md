# Q1466: nft-metadata via useNFTCoinAdded 1466

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTCoinAdded` (packages/api-react/src/hooks/useNFTCoinAdded.ts) control filename and MIME/type mismatch during download with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinAdded.ts` / `useNFTCoinAdded`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with reordered RPC events
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

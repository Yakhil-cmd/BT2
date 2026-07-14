# Q2414: nft-metadata via NFTInfo 2414

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTInfo` (packages/api/src/@types/NFTInfo.ts) control content hash/status fields that change across fetches after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTInfo.ts` / `NFTInfo`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; after a failed RPC response
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

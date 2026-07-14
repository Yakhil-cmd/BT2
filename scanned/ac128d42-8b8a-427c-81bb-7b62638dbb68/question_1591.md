# Q1591: nft-metadata via const 1591

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `const` (packages/gui/src/hooks/useFetchAndProcessMetadata.ts) control metadata URI list with mixed schemes and redirects with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useFetchAndProcessMetadata.ts` / `const`
- Entrypoint: multiple NFT download action
- Attacker controls: metadata URI list with mixed schemes and redirects; with reordered RPC events
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

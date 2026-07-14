# Q23: nft-metadata via getChangedEventName 23

## Question
Can an unprivileged attacker entering through the external NFT link open action in `getChangedEventName` (packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts) control content hash/status fields that change across fetches with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts` / `getChangedEventName`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with reordered RPC events
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

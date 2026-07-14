# Q2353: nft-metadata via handleInvalidate 2353

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `handleInvalidate` (packages/gui/src/hooks/useNFTMetadata.ts) control metadata URI list with mixed schemes and redirects after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMetadata.ts` / `handleInvalidate`
- Entrypoint: multiple NFT download action
- Attacker controls: metadata URI list with mixed schemes and redirects; after a failed RPC response
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

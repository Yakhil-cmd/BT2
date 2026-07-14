# Q151: nft-metadata via NFTAutocomplete 151

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTAutocomplete` (packages/gui/src/components/nfts/NFTAutocomplete.tsx) control metadata URI list with mixed schemes and redirects after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTAutocomplete.tsx` / `NFTAutocomplete`
- Entrypoint: multiple NFT download action
- Attacker controls: metadata URI list with mixed schemes and redirects; after a profile switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

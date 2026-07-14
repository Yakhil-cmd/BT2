# Q26: nft-metadata via useNFTDataNachos 26

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTDataNachos` (packages/gui/src/components/nfts/provider/hooks/useNFTDataNachos.ts) control objectionable-content flags and hidden NFT state with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTDataNachos.ts` / `useNFTDataNachos`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; with a delayed metadata fetch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

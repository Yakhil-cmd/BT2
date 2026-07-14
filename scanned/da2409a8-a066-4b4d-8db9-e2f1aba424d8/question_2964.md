# Q2964: nft-metadata via message 2964

## Question
Can an unprivileged attacker entering through the external NFT link open action in `message` (packages/gui/src/components/nfts/NFTHashStatus.tsx) control objectionable-content flags and hidden NFT state with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTHashStatus.tsx` / `message`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with a cached permission entry
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

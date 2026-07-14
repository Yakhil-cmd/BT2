# Q1095: nft-metadata via value 1095

## Question
Can an unprivileged attacker entering through the external NFT link open action in `value` (packages/gui/src/components/nfts/NFTFilterProvider.tsx) control objectionable-content flags and hidden NFT state with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTFilterProvider.tsx` / `value`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with case-normalized identifiers
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

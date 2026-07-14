# Q2952: nft-metadata via handleInputValueChange 2952

## Question
Can an unprivileged attacker entering through the external NFT link open action in `handleInputValueChange` (packages/gui/src/components/nfts/NFTAutocomplete.tsx) control metadata URI list with mixed schemes and redirects with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTAutocomplete.tsx` / `handleInputValueChange`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; with a stale Redux cache
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

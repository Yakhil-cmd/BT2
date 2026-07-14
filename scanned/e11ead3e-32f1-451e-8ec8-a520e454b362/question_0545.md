# Q545: nft-metadata via NFTAttribute 545

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTAttribute` (packages/api/src/@types/NFTAttribute.ts) control filename and MIME/type mismatch during download with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTAttribute.ts` / `NFTAttribute`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; with hidden Unicode characters
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

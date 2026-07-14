# Q3502: nft-metadata via normalizeUrl 3502

## Question
Can an unprivileged attacker entering through the external NFT link open action in `normalizeUrl` (packages/gui/src/util/normalizeUrl.ts) control objectionable-content flags and hidden NFT state during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/normalizeUrl.ts` / `normalizeUrl`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; during a pending modal confirmation
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

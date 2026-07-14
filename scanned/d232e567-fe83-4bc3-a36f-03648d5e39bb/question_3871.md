# Q3871: nft-metadata via useNFTCoinDIDSet 3871

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useNFTCoinDIDSet` (packages/api-react/src/hooks/useNFTCoinDIDSet.ts) control content hash/status fields that change across fetches with a cached permission entry and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinDIDSet.ts` / `useNFTCoinDIDSet`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with a cached permission entry
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

# Q1821: nft-metadata via handleChangeHideObjectionableContent 1821

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `handleChangeHideObjectionableContent` (packages/gui/src/components/settings/SettingsNFT.tsx) control HTML/SVG/media content rendered in preview with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNFT.tsx` / `handleChangeHideObjectionableContent`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; with case-normalized identifiers
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

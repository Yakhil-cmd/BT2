# Q3689: nft-metadata via clearNFTCache 3689

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `clearNFTCache` (packages/gui/src/components/settings/SettingsNFT.tsx) control HTML/SVG/media content rendered in preview during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/settings/SettingsNFT.tsx` / `clearNFTCache`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; during a pending modal confirmation
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

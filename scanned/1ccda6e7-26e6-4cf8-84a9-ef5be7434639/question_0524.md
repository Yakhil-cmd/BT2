# Q524: external-file-url via index 524

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `index` (packages/gui/src/electron/components/SandboxedIframe/index.ts) control iframe content with navigation or message attempts through a batch of rapid user-accessible actions and drive the sequence open notification -> resolve details -> execute so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: remote JSON fetch helper
- Attacker controls: iframe content with navigation or message attempts; through a batch of rapid user-accessible actions
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

# Q2454: rpc-state via handleCopyToClipboard 2454

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `handleCopyToClipboard` (packages/gui/src/components/signVerify/SignMessageResultDialog.tsx) control subscription event for a different wallet/fingerprint after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignMessageResultDialog.tsx` / `handleCopyToClipboard`
- Entrypoint: camel/snake case transform path
- Attacker controls: subscription event for a different wallet/fingerprint; after a profile switch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

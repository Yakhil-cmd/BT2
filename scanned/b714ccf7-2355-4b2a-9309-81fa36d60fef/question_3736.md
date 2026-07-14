# Q3736: rpc-state via parseNotificationPayload 3736

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `parseNotificationPayload` (packages/gui/src/components/notification/utils.ts) control large numeric fields near JS precision limits with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/notification/utils.ts` / `parseNotificationPayload`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with reordered RPC events
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

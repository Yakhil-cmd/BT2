# Q2888: Unscoped status forces `release/gate`=success on a victim commit

## Question
Can an unprivileged attacker deliver a `status` webhook setting `context: release/gate`, `state: success` for a SHA shared with a victim stack, so `StatusHandler#process` rewrites that required context across repositories and changes the victim commit's `deployable?`/merge eligibility?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the status payload `sha`, `context: release/gate`, `state: success`; attacker owns a repo producing that SHA
- Exploit idea: `StatusHandler` writes the status to every commit with that SHA regardless of repository; if `release/gate` is in the victim's `ci.require`, its `success` flips deployability/merge
- Invariant to test: A required-context status only affects the repository that authenticated the status event.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed a victim stack requiring `release/gate`, share the SHA, process the crafted status, assert the victim commit's status group and deployable? changed.

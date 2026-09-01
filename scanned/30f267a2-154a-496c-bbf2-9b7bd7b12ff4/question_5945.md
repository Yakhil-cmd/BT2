# Q5945: Unscoped status forces `ci/lint`=failure on a victim commit

## Question
Can an unprivileged attacker deliver a `status` webhook setting `context: ci/lint`, `state: failure` for a SHA shared with a victim stack, so `StatusHandler#process` rewrites that required context across repositories and changes the victim commit's `deployable?`/merge eligibility?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the status payload `sha`, `context: ci/lint`, `state: failure`; attacker owns a repo producing that SHA
- Exploit idea: `StatusHandler` writes the status to every commit with that SHA regardless of repository; if `ci/lint` is in the victim's `ci.require`, its `failure` flips deployability/merge
- Invariant to test: A required-context status only affects the repository that authenticated the status event.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: seed a victim stack requiring `ci/lint`, share the SHA, process the crafted status, assert the victim commit's status group and deployable? changed.

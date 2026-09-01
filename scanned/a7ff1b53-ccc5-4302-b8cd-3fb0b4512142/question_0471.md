# Q0471: [owner/full_name split] `status` -> StatusHandler on a review_stacks_enabled false stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `status` event against a victim stack where review_stacks_enabled false, can an unprivileged attacker make `StatusHandler` (runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all) cause impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has review_stacks_enabled false
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all; review stacks are supposedly disabled yet the provision? precedence bug still provisions amplifies the effect
- Invariant to test: A `status` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `owner/full_name split`, forge `status` for a review_stacks_enabled false stack, assert the downstream effect.

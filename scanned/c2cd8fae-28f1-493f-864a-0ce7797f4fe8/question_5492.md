# Q5492: [owner/full_name split] `pull_request` action=`assigned` -> AssignedHandler on a review_stacks_enabled false stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `pull_request` action=`assigned` event against a victim stack where review_stacks_enabled false, can an unprivileged attacker make `AssignedHandler` (updates the persisted `PullRequest` record on assignee change) cause impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`assigned`, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has review_stacks_enabled false
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `AssignedHandler` updates the persisted `PullRequest` record on assignee change; review stacks are supposedly disabled yet the provision? precedence bug still provisions amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `owner/full_name split`, forge `pull_request` action=`assigned` for a review_stacks_enabled false stack, assert the downstream effect.

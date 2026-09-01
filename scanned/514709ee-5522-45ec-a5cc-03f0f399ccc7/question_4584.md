# Q4584: [owner/full_name split] `push` -> PushHandler on a review_stacks_enabled true, allow_all stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `push` event against a victim stack where review_stacks_enabled true, allow_all, can an unprivileged attacker make `PushHandler` (syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery) cause impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery; external PRs auto-provision review stacks that execute shipit.yml amplifies the effect
- Invariant to test: A `push` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `owner/full_name split`, forge `push` for a review_stacks_enabled true, allow_all stack, assert the downstream effect.

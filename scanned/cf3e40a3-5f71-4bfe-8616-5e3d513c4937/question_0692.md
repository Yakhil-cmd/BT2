# Q0692: [owner/full_name split] `pull_request` action=`labeled` -> LabeledHandler on a review_stacks_enabled true, allow_all stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `pull_request` action=`labeled` event against a victim stack where review_stacks_enabled true, allow_all, can an unprivileged attacker make `LabeledHandler` (archives or unarchives the review stack based on the provisioning label) cause impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`labeled`, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `LabeledHandler` archives or unarchives the review stack based on the provisioning label; external PRs auto-provision review stacks that execute shipit.yml amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `owner/full_name split`, forge `pull_request` action=`labeled` for a review_stacks_enabled true, allow_all stack, assert the downstream effect.

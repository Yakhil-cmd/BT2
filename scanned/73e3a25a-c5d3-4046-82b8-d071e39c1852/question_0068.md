# Q0068: [owner/full_name split] `pull_request` action=`opened` -> LabelCapturingHandler on a shared commit SHA with attacker repo stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `pull_request` action=`opened` event against a victim stack where shared commit SHA with attacker repo, can an unprivileged attacker make `LabelCapturingHandler` (persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`) cause impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has shared commit SHA with attacker repo
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `LabelCapturingHandler` persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`; a status/commit lookup by bare SHA collides with the victim's commit amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `owner/full_name split`, forge `pull_request` action=`opened` for a shared commit SHA with attacker repo stack, assert the downstream effect.

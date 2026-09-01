# Q0996: [organization fallback selection] `pull_request` action=`reopened` -> LabelCapturingHandler on a bot_login configured (Shipit.user) stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `pull_request` action=`reopened` event against a victim stack where bot_login configured (Shipit.user), can an unprivileged attacker make `LabelCapturingHandler` (persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`) cause impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`reopened`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has bot_login configured (Shipit.user)
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `LabelCapturingHandler` persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`; auto-triggered deploys run as the configured bot identity amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `organization fallback selection`, forge `pull_request` action=`reopened` for a bot_login configured (Shipit.user) stack, assert the downstream effect.

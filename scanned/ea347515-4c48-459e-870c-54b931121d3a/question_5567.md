# Q5567: Forged `pull_request` action=`unlabeled` vs a stack where org configured without webhook_secret (LabelCapturingHandler)

## Question
Against a victim stack where org configured without webhook_secret (forged webhooks for this org are accepted unconditionally), can an unprivileged attacker forge a `pull_request` action=`unlabeled` webhook for an org with no configured webhook_secret so `LabelCapturingHandler`, which persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, produces impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unlabeled`, event header, signature; targets an org with no webhook_secret and a stack where org configured without webhook_secret
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `LabelCapturingHandler` persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, and because forged webhooks for this org are accepted unconditionally the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: configure a stack with org configured without webhook_secret, forge the `pull_request` event, assert the amplified downstream effect occurred.

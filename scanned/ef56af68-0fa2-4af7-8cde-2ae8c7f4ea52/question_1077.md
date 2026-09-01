# Q1077: Forged `pull_request` action=`opened` vs a stack where ignore_ci true (LabelCapturingHandler)

## Question
Against a victim stack where ignore_ci true (`Commit#deployable?` short-circuits CI so any commit is shippable), can an unprivileged attacker forge a `pull_request` action=`opened` webhook for an org with no configured webhook_secret so `LabelCapturingHandler`, which persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, produces impact because `Commit#deployable?` short-circuits CI so any commit is shippable?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, event header, signature; targets an org with no webhook_secret and a stack where ignore_ci true
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `LabelCapturingHandler` persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, and because `Commit#deployable?` short-circuits CI so any commit is shippable the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with ignore_ci true, forge the `pull_request` event, assert the amplified downstream effect occurred.

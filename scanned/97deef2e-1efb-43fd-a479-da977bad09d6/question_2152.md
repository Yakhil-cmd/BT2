# Q2152: Forged `pull_request` action=`labeled` vs a stack where review_stacks_enabled true, allow_all (LabelCapturingHandler)

## Question
Against a victim stack where review_stacks_enabled true, allow_all (external PRs auto-provision review stacks that execute shipit.yml), can an unprivileged attacker forge a `pull_request` action=`labeled` webhook for an org with no configured webhook_secret so `LabelCapturingHandler`, which persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, produces impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`labeled`, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled true, allow_all
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `LabelCapturingHandler` persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, and because external PRs auto-provision review stacks that execute shipit.yml the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled true, allow_all, forge the `pull_request` event, assert the amplified downstream effect occurred.

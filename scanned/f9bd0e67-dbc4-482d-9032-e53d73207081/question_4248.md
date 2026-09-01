# Q4248: Forged `status` vs a stack where review_stacks_enabled true, allow_all (StatusHandler)

## Question
Against a victim stack where review_stacks_enabled true, allow_all (external PRs auto-provision review stacks that execute shipit.yml), can an unprivileged attacker forge a `status` webhook for an org with no configured webhook_secret so `StatusHandler`, which runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all, produces impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled true, allow_all
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all, and because external PRs auto-provision review stacks that execute shipit.yml the effect is amplified
- Invariant to test: A forged `status` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled true, allow_all, forge the `status` event, assert the amplified downstream effect occurred.

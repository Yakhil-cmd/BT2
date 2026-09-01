# Q3527: [organization fallback selection] `membership` action=`removed` -> MembershipHandler on a review_stacks_enabled true, allow_all stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `membership` action=`removed` event against a victim stack where review_stacks_enabled true, allow_all, can an unprivileged attacker make `MembershipHandler` (creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads) cause impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads; external PRs auto-provision review stacks that execute shipit.yml amplifies the effect
- Invariant to test: A `membership` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `organization fallback selection`, forge `membership` action=`removed` for a review_stacks_enabled true, allow_all stack, assert the downstream effect.

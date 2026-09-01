# Q2941: [unknown-organization error path] `membership` action=`added` -> MembershipHandler on a blocking_statuses configured stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `membership` action=`added` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `MembershipHandler` (creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`added`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has blocking_statuses configured
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `membership` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `unknown-organization error path`, forge `membership` action=`added` for a blocking_statuses configured stack, assert the downstream effect.

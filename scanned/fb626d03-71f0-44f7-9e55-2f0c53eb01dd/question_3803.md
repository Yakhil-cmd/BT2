# Q3803: [unknown-organization error path] `membership` action=`removed` -> MembershipHandler on a production environment stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `membership` action=`removed` event against a victim stack where production environment, can an unprivileged attacker make `MembershipHandler` (creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads) cause impact because the affected stack is the production environment?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has production environment
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads; the affected stack is the production environment amplifies the effect
- Invariant to test: A `membership` event only affects the repository/stack whose secret authenticated it, regardless of production environment.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `unknown-organization error path`, forge `membership` action=`removed` for a production environment stack, assert the downstream effect.

# Q5193: Forged `membership` removed webhook via owner/full_name split reaches MembershipHandler

## Question
Can an unprivileged internet user POST a `membership` event (action=`removed`) to `/webhooks` that names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: membership` header, and `X-Hub-Signature`; specifically it names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; the accepted body then drives `Shipit::Webhooks::Handlers::MembershipHandler` which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `membership` body, assert the handler ran and mutated a record owned by a different org.

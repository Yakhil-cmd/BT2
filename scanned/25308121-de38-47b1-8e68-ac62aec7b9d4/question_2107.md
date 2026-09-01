# Q2107: Forged `membership` added webhook via legacy sha1 signature header reaches MembershipHandler

## Question
Can an unprivileged internet user POST a `membership` event (action=`added`) to `/webhooks` that supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: membership` header, and `X-Hub-Signature`; specifically it supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; the accepted body then drives `Shipit::Webhooks::Handlers::MembershipHandler` which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `membership` body, assert the handler ran and mutated a record owned by a different org.

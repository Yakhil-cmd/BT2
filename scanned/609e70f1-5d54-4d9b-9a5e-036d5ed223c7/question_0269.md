# Q0269: Forged `pull_request` assigned webhook via owner/full_name split reaches AssignedHandler

## Question
Can an unprivileged internet user POST a `pull_request` event (action=`assigned`) to `/webhooks` that names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::PullRequest::AssignedHandler` updates the persisted `PullRequest` record on assignee change, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: pull_request` header, and `X-Hub-Signature`; specifically it names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; the accepted body then drives `Shipit::Webhooks::Handlers::PullRequest::AssignedHandler` which updates the persisted `PullRequest` record on assignee change
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `pull_request` body, assert the handler ran and mutated a record owned by a different org.

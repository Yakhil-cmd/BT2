# Q0778: owner/full_name split -> insert the attacker into a monitored team

## Question
Chaining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `membership` handler, can an unprivileged attacker insert the attacker into a monitored team on a repository they do not own?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body plus signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates, and the accepted `membership` event lets the attacker insert the attacker into a monitored team
- Invariant to test: A forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it.
- Expected Immunefi impact: High — Privilege escalation into Shipit.github_teams authorization
- Fast validation: minitest: forge the `membership` event under the `owner/full_name split` condition, assert the downstream mutation for the victim occurred.

### Title
Webhook `pull_request` events verified against `repository.owner.login`'s secret are applied to a different repository named by `repository.full_name`, letting an attacker with any no-secret org mutate a victim's continuous-deployment review stack - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the signing secret using `repository.owner.login` (via `repository_owner`), but every `PullRequest` handler resolves the actual repository/stack to mutate via `params.repository.full_name`, an independent, unauthenticated field. Combined with `GitHubApp#verify_webhook_signature` returning `true` when no `webhook_secret` is configured for the selected organization, an attacker can pick any multi-org-configured organization that lacks a `webhook_secret` to trivially "pass" verification while pointing `full_name` at a victim org's repository/stack.

### Finding Description
The broken binding: the code assumes `repository_owner == owner_of(repository.full_name)`, but nothing enforces this equality.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) does:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` (line 59-62) reads `params.dig('repository', 'owner', 'login')`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83): `return true unless webhook_secret`. If the organization resolved by `repository_owner` has no `webhook_secret` configured in `Shipit.github_app_config`, signature verification is bypassed entirely — any payload, any signature (even absent), is accepted.
- After passing `verify_signature`, `WebhooksController#create` dispatches `params` unchanged to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (app/controllers/shipit/webhooks_controller.rb:10-15).
- `LabelCapturingHandler#repository` (app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114) resolves the target repo via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — completely independent of `repository_owner` used for signature selection.
- On `action=opened`, `capture_labels?`/`opened_active_stack?` requires only `stack.present?` (lines 51-59), then `capture_labels` (lines 98-102) does `pull_request.update!(labels: params.pull_request.labels.map(&:name))` on the victim's existing `PullRequest`.
- `ReviewStack#env` (app/models/shipit/review_stack.rb:84-93) uppercases each label name into an env var set to `"true"`, merged into deploy/task env (confirmed by `StackCommands#env`, `test/lib/shipit/deploy_commands_test.rb`, `test/models/shipit/review_stack_test.rb`).
- If the victim stack has `continuous_deployment: true`, any newly green commit triggers `ContinuousDeliveryJob#perform` → `stack.trigger_continuous_delivery` → `Deploy` with `stack.env` merged in (app/jobs/shipit/continuous_delivery_job.rb:10-21, app/models/shipit/stack.rb:210-229, lib/shipit/stack_commands.rb:13-15), executing attacker-chosen label-derived environment variables inside the deploy command execution for a repository/stack the attacker never authenticated against.

Existing guards do not catch this: `drop_unhandled_event` only checks event type presence; `ExplicitParameters` schema only validates types/shape, not cross-field consistency between `repository.owner.login` and `repository.full_name`; there is no code anywhere comparing these two fields.

### Impact Explanation
An attacker who controls (or names) any GitHub organization/repository configured in Shipit's multi-org `secrets.github` map without a `webhook_secret` set can forge a `pull_request` `opened` webhook whose `repository.owner.login` is that no-secret org while `repository.full_name` names any victim repository/stack Shipit already tracks. This lets the attacker inject arbitrary labels (hence arbitrary uppercase env vars set to `"true"`) into the victim's `ReviewStack`, which are merged into the environment of subsequent deploy/rollback/task command execution (`Command`/`PTY.spawn` context) — for a repository that did not authenticate the webhook. If the victim stack has `continuous_deployment` enabled, this happens automatically once CI reports green on any pending commit, giving the attacker influence over the deploy environment without any Shipit credentials. This is a payload for one repository mutating another repository's stack/PullRequest record and its subsequent deploy execution — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Preconditions: Shipit must be configured with the multi-org GitHub App config schema (`github_default_organization` non-nil, i.e., `secrets.github` keyed by org names) and at least one configured organization must lack a `webhook_secret` (or the attacker's own org, which they legitimately control, may itself lack one). The victim repository/stack must exist in Shipit's DB with an active `ReviewStack`/`PullRequest`, and `continuous_deployment: true` for full auto-deploy amplification (label-injection into `PullRequest.labels`/`ReviewStack#env` occurs regardless of continuous_deployment). No GitHub secrets, Shipit session, or API token are required — only the ability to send an HTTP POST to `/webhooks`. This is trivially repeatable against any tracked repository by simply changing `repository.full_name` in the JSON body per request.

### Recommendation
Verify that `repository.full_name`'s owner matches `repository_owner`/the organization whose secret validated the signature before dispatching to handlers (reject if they diverge), and/or require `webhook_secret` to be present (never silently bypass verification) for every configured organization, and have handlers key resolution off the same organization value used for signature verification rather than an unauthenticated payload field.

### Proof of Concept
Minitest plan (under `test/controllers/webhooks_controller_test.rb`, no live GitHub):
1. Configure two orgs in test credentials: `attacker-org` (no `webhook_secret`) and `victim-org` (has `webhook_secret`, e.g. `"expected"`).
2. Create `shipit_repositories(:victim_org_repo)` under `victim-org/repo`, a `Shipit::Stack` with `continuous_deployment: true`, and a `ReviewStack`/`PullRequest` fixture with `number: 1`, `labels: []`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no or arbitrary `X-Hub-Signature`, and JSON body:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { ..., "labels": [{"name": "MALICIOUS_ENV"}] },
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/repo" },
  "sender": {"login": "attacker"}
}
```
4. Assert response is `200 OK` (verification bypassed because `attacker-org` has no `webhook_secret`).
5. Assert `pull_request.reload.labels == ["MALICIOUS_ENV"]` — i.e., the victim's stack's `PullRequest` record, which never authenticated this webhook, was mutated.
6. Assert `stack.env["MALICIOUS_ENV"] == "true"`.
7. Optionally assert that `ContinuousDeliveryJob.perform_later` was enqueued with `deploy.env` containing `"MALICIOUS_ENV" => "true"` upon a subsequent green commit status, demonstrating downstream deploy impact — equality check: `repository_owner ("attacker-org") != owner_of(params.repository.full_name) ("victim-org")` yet the mutation succeeded, proving the binding is broken.
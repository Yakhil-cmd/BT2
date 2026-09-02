### Title
`push` webhook signature verified against `repository.owner.login` while stack mutation is scoped by an independent `repository.full_name` field, enabling cross-repo commit injection via `PushHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the signing organization from `params.dig('repository','owner','login')`, but `Handler#stacks` (used by `PushHandler`) resolves the target repository from the independent JSON field `payload.dig('repository','full_name')`. Because these two fields are never checked for consistency, an attacker who controls the raw JSON body of an unauthenticated `POST /webhooks` request can pick a configured org with no `webhook_secret` for `repository.owner.login` (which makes `GitHubApp#verify_webhook_signature` return `true` unconditionally) while pointing `repository.full_name` at a completely different, victim-owned repository/stack.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces:

`params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`

This is false whenever the attacker crafts the JSON differently, and nothing checks it.

Path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (`webhooks_controller.rb:59-62`) reads `params.dig('repository','owner','login')`.
2. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`): `return true unless webhook_secret`. If the org named by `repository.owner.login` has no `webhook_secret` configured, the signature check is bypassed entirely — any payload passes, regardless of the `X-Hub-Signature` header.
3. `WebhooksController#create` then dispatches to `Shipit::Webhooks.for_event('push')`, invoking `PushHandler.call(params)`.
4. `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`.
5. `stacks` comes from the base `Handler` class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`): `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name = payload.dig('repository', 'full_name')` — a field completely independent of the one used in step 1's org lookup.
6. `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) splits `full_name` on `/` and does a DB lookup by `owner`/`name`, resolving whatever real repository/stack the attacker names, with no relation to the org that "verified" the request.
7. `stack.sync_github(expected_head_sha:)` enqueues `GithubSyncJob` (`app/jobs/shipit/github_sync_job.rb`), which fetches commits from GitHub for that stack's real repository and calls `append_commit`/`stack.commits.create_from_github!`, mutating the victim stack's commit history/state, and can flip stack accessibility (`mark_as_accessible!`/`mark_as_inaccessible!`).

Existing guards do not catch this:
- `drop_unhandled_event` only checks the event type exists.
- `verify_signature` only verifies against the org named in `repository.owner.login`; it never compares against `repository.full_name`.
- `ExplicitParameters` schema for `PushHandler` only requires `ref` and `after` — it does not validate `repository.full_name` against `repository.owner.login`.
- No model validation ties webhook-owner authentication to the resolved `Repository`.

### Impact Explanation
An attacker who can name an org configured in Shipit but lacking a `webhook_secret` (their own, or any misconfigured/no-secret org) can forge a `push` payload whose `repository.full_name` points at any other, victim-owned repository/stack tracked by Shipit. This drives `GithubSyncJob` to append real commits (fetched live from GitHub for the victim repo) into the victim stack, altering `undeployed_commits`, potentially unlocking/blocking deploys depending on `blocking_statuses` configuration and commit content (e.g., revert detection via `lock_reverted_commits!`). This is a payload for one repository (an unsecured org) mutating another repository's (victim org's) stack state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any stack whose repository full_name is known/guessable, with no session, token, or secret required.

### Likelihood Explanation
Preconditions: Shipit must have at least one configured GitHub org with `webhook_secret` unset (i.e., `@config[:webhook_secret]` blank in that org's config), and the attacker must know or guess a victim `owner/repo` full_name tracked by Shipit (repository names are not secret). No GitHub credentials, Shipit session, or API token is required — the endpoint is `POST /webhooks`, unauthenticated by design and only gated by per-org signature checks. Cost is a single crafted JSON HTTP request, fully repeatable and scriptable against many stacks/branches.

### Recommendation
Enforce that the organization used to select/verify the webhook signature is the same organization that owns the repository resolved from `full_name` before dispatching to any handler — e.g., derive `repository_owner` strictly from `repository.full_name.split('/').first` (not `repository.owner.login`), or explicitly assert `repository.owner.login.downcase == repository.full_name.split('/').first.downcase` in `WebhooksController#verify_signature`/`#create` and reject (422) on mismatch. Additionally, treat a missing/blank `webhook_secret` for an org as a configuration error (fail closed) rather than "trust everything" (`return true unless webhook_secret`).

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (existing file, extend it):
1. Configure two orgs in `Shipit.github_config`/`Shipit.github`: `"no-secret-org"` with no `webhook_secret`, and `"victim-org"` with a `webhook_secret` set.
2. Create `victim_repo = Shipit::Repository.create!(owner: "victim-org", name: "victim-repo")` and a `Stack` on it with `branch: "master"` and a deploy spec with `blocking_statuses` configured; record `stack.commits.count` before.
3. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (or a bogus one), and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<victim commit sha>",
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Assert response is `200 OK` (not `422`), proving signature verification for `no-secret-org` (equality LHS) passed while the mutated resource belongs to `victim-org` (equality RHS) — i.e. `repository_owner ("no-secret-org") != full_name.split('/').first ("victim-org")` yet the request was accepted and dispatched.
5. Assert `GithubSyncJob` was enqueued with `stack_id: victim_stack.id, expected_head_sha: "<victim commit sha>"` (via `assert_enqueued_with`), demonstrating that a payload "verified" under one org's (non-)secret caused a job to mutate a different org's stack — confirming the binding is broken and the invariant ("a push event only affects the repository/stack whose secret authenticated it") does not hold.
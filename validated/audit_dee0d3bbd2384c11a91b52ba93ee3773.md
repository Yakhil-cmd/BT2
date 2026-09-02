### Title
Cross-repository status forgery flips `Commit#deployable?` via unscoped sha lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, which is not scoped to the repository/stack that the webhook payload names. Any repository whose commit history shares a sha with a commit tracked by a different Shipit stack (e.g. a public fork sharing pre-fork history with the upstream repo) can post a signed `success` status from its own webhook and have that status attached to the unrelated stack's commit, flipping `Commit#deployable?` and defeating the `require_ci` guard in `Api::DeploysController#create`.

### Finding Description
Broken binding, stated as an equality that does NOT hold:
`stack_consulted_by_DeploysController#create` (obtained via `stack.commits.by_sha(params.sha)`, i.e. `commit.stack_id == stack.id` for the deploying stack) is assumed to equal `stack_whose_statuses_were_written_by_StatusHandler` (derived only from `params.sha`, with zero reference to `params['repository']['full_name']`).

Code path:
- `WebhooksController#verify_signature` only checks the HMAC signature against the GitHub App for `repository_owner` (`params.dig('repository','owner','login')`) [1](#0-0)  - it authenticates that the payload really came from that named repository/org, but never binds the payload to any specific Shipit stack.
- `StatusHandler#process` then does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1)  - this query is global across all stacks/repositories in the Shipit instance; it never filters by `commit.stack.repository` or by `params['repository']['full_name']`.
- `Commit#create_status_from_github!` unconditionally records the new status: `statuses.replicate_from_github!(stack_id, github_status)` [3](#0-2) .
- `Commit#deployable?` is purely a function of the commit's own `statuses`/`locked?`/stack flags: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [4](#0-3) .
- `Api::DeploysController#create` looks up the commit strictly through the deploying stack (`stack.commits.by_sha(params.sha)`) and then trusts `commit.deployable?` for the `require_ci` gate: [5](#0-4) .

Exploit flow: an attacker who owns/forks a repository that shares one or more commit shas with a repository tracked by a victim Shipit stack (a very common situation for public forks, since Git commit hashes are content-addressed and unchanged commits keep identical shas across forks) sets a `success` commit status via the GitHub API on their own repo for that shared sha (or simply pushes/enables a CI integration that reports success). GitHub signs and delivers this as a legitimate `status` webhook naming the attacker's own repository. `verify_signature` passes because the signature genuinely matches the attacker's own org/app. `StatusHandler` then attaches this status to every `Commit` row across the entire Shipit instance that has that sha - including the victim stack's row - because the lookup is not scoped to the originating repository. This flips the victim commit's `deployable?` from `false` to `true` with no status ever having come from the victim repository's own CI.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`, and the `stack.commits.by_sha` scoping in `DeploysController`) all check different things - which repo signed the payload, whether the event type is handled, and which stack's commit the deploy targets - but none of them verify that the repository named in the webhook payload matches the repository of the stack that owns the `Commit` row being mutated. That is precisely the missing check.

### Impact Explanation
An unrelated, attacker-controlled repository's webhook can write `Status` rows onto a commit belonging to a stack it does not own, causing `Commit#deployable?` to become `true` for that victim commit. If a caller who holds legitimate `deploy` permission for the victim stack (an "authenticated but unrelated" request in the sense that they didn't intend to bypass CI, or an automated/CD pipeline relying on `require_ci: true`) subsequently deploys that sha, `Api::DeploysController#create`'s CI safety gate is silently bypassed, letting a deploy proceed as if CI had passed when it had not. This matches the "unauthorized deploy" / "payload for one repository mutating another's stack" Critical category. It is repeatable against any pair of stacks whose repositories ever share a commit sha (most naturally: forks of the same upstream repository), and it does not require any Shipit credentials - only ordinary GitHub repository ownership and the ability to set a commit status or trigger any check that posts a `status` event.

### Likelihood Explanation
Requires: (1) a Shipit-tracked stack whose repository has a fork or otherwise shares git history/shas with a repository the attacker controls; (2) the shared commit exists as a `Commit` row in the victim stack (i.e., Shipit ingested it, which happens automatically for any commit reachable from the tracked branch); (3) GitHub's App/webhook integration is enabled for the attacker's own repository (a normal, low-cost precondition for any repo owner). No secrets, no privileged Shipit role, and no interaction with the victim repository are required - the attacker only acts on their own repository. This is a realistic and cheap attack: forking a public repository and shared history is extremely common, and Shipit does not need to intentionally track the fork - only the shared sha needs to exist as a `Commit` row somewhere in the instance.

### Recommendation
Scope `StatusHandler#process` (and any other sha-keyed handler with the same pattern) to commits whose `stack.repository` matches the `repository` named in the webhook payload, e.g. join through `Stack`/`Repository` and filter by `full_name`/`owner`/`name` derived from `params['repository']`, instead of a bare `Commit.where(sha: params.sha)`. Apply the same repository-scoping check anywhere else in the webhook handlers that looks up records purely by `sha` without validating the payload's repository against the record's owning stack.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create two `Stack`s, `victim_stack` (repository `victim/repo`) and `attacker_stack` is not even necessary - only a `Commit` row for `victim_stack` with a fixed `sha = "a" * 40` and no statuses, so `commit.deployable?` is initially `false` (no success status yet).
2. Build a `Shipit::Webhooks::Handlers::StatusHandler` params payload with `sha: "a" * 40`, `state: "success"`, and `repository: { full_name: "attacker/fork", owner: { login: "attacker" } }` - i.e., a payload naming a completely different repository than `victim/repo`.
3. Assert before: `commit.reload.deployable?` is `false`.
4. Invoke `StatusHandler.new.call(payload)` (or the handler entry point used by `Shipit::Webhooks.for_event`), bypassing only the outer `WebhooksController` signature check (since that's orthogonal - it only proves the payload's own repo, not the target commit's repo).
5. Assert after: `commit.reload.deployable?` is now `true`, and assert `commit.statuses.last.stack_id == victim_stack.id` while the payload's repository (`attacker/fork`) never equals `victim_stack.repository.full_name`, proving the write happened without any status originating from the victim's own repository.
6. Optionally chain into `Api::DeploysController#create` params validation logic directly: confirm `param_error!(:require_ci, ...)` is skipped because `commit.deployable?` is now true, demonstrating the downstream bypass.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-23)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

```

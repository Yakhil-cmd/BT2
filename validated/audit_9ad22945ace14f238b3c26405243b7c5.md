Confirmed: every other handler (`PushHandler`, `CheckSuiteHandler`, all `pull_request/*_handler.rb`) scopes its query through `stacks`, which is derived from `Repository.from_github_repo_name(repository_name)` using `payload.dig('repository', 'full_name')` [1](#0-0)  and [2](#0-1) . `StatusHandler#process`, however, queries `Commit.where(sha: params.sha)` globally, with no repository/stack scoping at all [3](#0-2) .

### Title
Cross-repository blocking-status bypass via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, ignoring the repository named in the webhook payload, unlike every other webhook handler in the engine which scopes lookups through `stacks` (derived from `repository.full_name`). If a `Commit` row with the same SHA exists on an unrelated stack (e.g. because both stacks tracked commits with byte-identical content, since git SHAs are content-addressed and reproducible from public data), a status webhook signed only for the attacker's own organization can flip that commit's status/state on the victim's stack.

### Finding Description
The broken binding is: `stack_whose_blocking_statuses_apply(commit) == stack_that_authenticated_this_webhook(payload)`. This should always hold, but `StatusHandler#process` never enforces it.

Path: `WebhooksController#create` verifies the HMAC signature only against `Shipit.github(organization: repository_owner)`, i.e. it proves the payload was legitimately sent by *an* org configured in Shipit and matching `repository.owner.login` in the payload [4](#0-3) . It does **not** prove any relationship between the payload's repository and the `Commit` row that ultimately gets mutated. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
This iterates over **every** `Commit` row across **all** stacks/repositories sharing that SHA — it never restricts to `stacks` (the `Repository.from_github_repo_name(repository_name).stacks` scope used by `PushHandler`, `CheckSuiteHandler`, and the `pull_request/*` handlers) [1](#0-0) .

`create_status_from_github!` creates a `Status` record tied to that commit and its stack [5](#0-4) , and `Commit#blocked?` re-evaluates `stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)` [6](#0-5) , where `blocking?` is `!success? && commit.blocking_statuses.include?(context)` [7](#0-6) . Flipping the older commit's status to `success` for the matching `context` therefore flips `blocked?` to `false` for every newer undeployed commit on the victim stack, and `Commit#deployable?` consults `blocked?` directly [8](#0-7) .

Exploit flow: attacker constructs a git commit object byte-identical to a known public commit that exists (and is blocking) on the victim stack — reproducing an identical SHA requires only reproducing the same tree/parents/author/committer/timestamps/message, all of which are public data for open commits, not a SHA-1 collision break. Attacker pushes it into a repository they own/control and where they can trigger a real, validly-signed GitHub status webhook (owner login = attacker's org, matching a `GitHubApp` config Shipit trusts). Since `verify_signature` only checks that the *sender org* is legitimate, not that the *target commit's stack* belongs to that org, the webhook is accepted and `StatusHandler` updates the colliding `Commit` row wherever it exists, including on the victim's unrelated stack.

Existing guards do not catch this: `verify_signature` authenticates the sender org, not the commit-to-stack relationship [9](#0-8) ; the `ExplicitParameters` schema only validates shape of `sha`/`state`/etc, not ownership [10](#0-9) ; and no model validation ties a `Status`'s legitimacy to the requesting repository.

### Impact Explanation
An attacker can flip the `blocked?` gate to `false` for a victim stack's continuous-delivery pipeline without ever touching the victim's repository or possessing any Shipit credential, enabling an unauthorized deploy of code that never passed the blocking CI/compliance check — this is a payload for one repository mutating another's stack/commit state, matching the "Critical" impact category (unauthorized deploy / cross-repo mutation). Blast radius spans any stack across any tenant whose commit history happens to contain (or can be made to contain) a colliding SHA with attacker-controlled content.

### Likelihood Explanation
Preconditions: the victim stack must have `ci.blocking` contexts configured [11](#0-10) , an older undeployed commit currently blocking, and the attacker must control a repository capable of emitting a validly-signed webhook to the same Shipit instance (their own org, or a repo where the relevant GitHub App is installed). The nontrivial part is producing a `Commit` row collision: this requires either (a) both the victim's and attacker's repos legitimately sharing history/commit content (e.g. forks, shared upstream, vendored code, cherry-picks) — a realistic, low-cost scenario — or (b) deliberately reconstructing byte-identical commit objects, which is feasible without breaking SHA-1 since git commit inputs (tree, parents, author/committer, timestamps, message) are all public. This is not a purely theoretical finding but requires specific SHA-collision setup that a background agent should validate against real fixture data before treating as unconditionally exploitable in all deployments.

### Recommendation
Scope `StatusHandler#process` (and its underlying query) to the repository named in the payload, mirroring the pattern used by every other handler: filter via `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` or equivalent, so a `Commit` is only updated if it belongs to a stack whose `Repository` matches `payload.dig('repository', 'full_name')`. Additionally consider adding a uniqueness constraint / lookup scoping at the `Commit` model level (`stack_id` + `sha`) rather than a bare `Commit.where(sha:)`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_victim` (repository `victim/repo`) with `cached_deploy_spec` containing `ci.blocking = ['soc/compliance']`.
2. Create `commit_a` on `stack_victim` with `sha: 'deadbeef...'`, with a `pending` status for context `soc/compliance` (so `blocking? == true`).
3. Create `commit_b` on `stack_victim`, newer than `commit_a`, with a passing status — assert `commit_b.blocked?` is `true` (binding: `stack_victim.blocking_statuses` gates `commit_b`).
4. Create `stack_attacker` (repository `attacker/repo`) and a `Commit` row with the **same** `sha: 'deadbeef...'` as `commit_a`, belonging to `stack_attacker`.
5. Build a status webhook payload: `{ sha: 'deadbeef...', state: 'success', context: 'soc/compliance', repository: { full_name: 'attacker/repo', owner: { login: 'attacker' } } }`.
6. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature stubbing, as in existing tests that stub `verify_signature`).
7. Assert `commit_a.reload.blocking?` is now `false` and `commit_b.reload.blocked?` is now `false`, even though the webhook's `repository.full_name` was `attacker/repo`, not `victim/repo` — proving `stack_victim`'s blocking gate was bypassed by a payload authenticated only for the attacker's repository.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```

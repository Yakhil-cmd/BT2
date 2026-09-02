### Title
Global `Commit.where(sha:)` lookup in `StatusHandler#process` lets a sha-collision commit crafted in an attacker-owned repo write a `Status` onto a victim stack's commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit with an unscoped `Commit.where(sha: params.sha)` query, and the `commits` table only enforces sha uniqueness per `(sha, stack_id)` pair rather than globally. Because git commit shas are content-addressed and thus deterministically reproducible (e.g. via `git cherry-pick` of the exact commit object into a repo the attacker controls), an attacker can create a commit with a sha identical to a victim's tracked commit in a different stack/organization, and a legitimately-signed GitHub status webhook for the attacker's own repo will then be applied to the victim's commit as well.

### Finding Description
The binding required for `Commit.where(sha:)` to be safe is: `sha -> exactly one (organization, stack)`. The actual schema enforces only `sha, stack_id -> unique`, per the migration [1](#0-0) , i.e. the composite pair is unique, but the same `sha` value is free to exist under many different `stack_id`s belonging to different organizations. There is no global uniqueness constraint on `sha` alone anywhere in the schema or model, so the claimed binding is false — one sha can map to N stacks across N tenants.

Code path:
1. `WebhooksController#create` parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [2](#0-1) .
2. `verify_signature` resolves the GitHub App/secret to check against using `repository_owner`, i.e. the org named in the *incoming payload's own repository* field [3](#0-2) [4](#0-3) . This check only proves the webhook genuinely came from GitHub for the repository named in the payload — it says nothing about which `Commit` rows in the database that sha is allowed to touch.
3. `StatusHandler#process` then performs a completely unscoped query: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . Unlike the base `Handler` class, which exposes a `stacks` helper scoped by `repository_name` from the payload [6](#0-5) , `StatusHandler` never uses it, so the query is not filtered by the repository/stack that actually sent the webhook.
4. `create_status_from_github!` writes a real `Status` record tied to whichever commit/stack the sha happens to match [7](#0-6) , and that status feeds directly into `deployable?`/`blocked?`/continuous-delivery scheduling for the victim stack [8](#0-7) [9](#0-8) .

Exploit flow: the attacker onboards (or already owns) any repository/organization tracked by the same Shipit instance, with its own legitimate GitHub webhook secret. The attacker identifies a victim commit's sha (shas are public, e.g. visible in the victim's public repo or Shipit UI). The attacker reproduces the identical commit object — same tree, parent, author, committer, message, timestamps — by cherry-picking that exact commit into their own repo, which is a normal, unprivileged git operation that yields the same SHA-1. They then trigger (or already have) a CI system on their own repo that posts a `status` event for that sha (this is a completely normal GitHub status webhook for their own repository, correctly signed by GitHub with their own org's secret). `verify_signature` passes because the signature genuinely matches GitHub's signing for the attacker's own org — it was never designed to authorize which `Commit` rows the payload may touch. `StatusHandler#process`'s unscoped `Commit.where(sha:)` then matches both the attacker's own commit row and the victim's commit row (since sha uniqueness is only enforced per stack, not globally), and writes a new `Status` onto the victim's commit.

None of the listed guards close this gap: `verify_signature` authenticates the source org, not the target records; `drop_unhandled_event` only filters event types; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not authorization scope; there is no `require_permission!`/`stacks`-scope check inside `StatusHandler#process` at all.

### Impact Explanation
An attacker who controls any repository onboarded to the same multi-tenant Shipit instance can deterministically inject a `Status` (e.g., a fabricated `"success"` state) onto a specific victim commit in a completely unrelated stack/organization, by intentionally colliding its sha. Since `deployable?` and continuous-delivery scheduling depend on aggregated status state [10](#0-9) [9](#0-8) , this can push an otherwise-unverified victim commit into a deployable state, triggering an unauthorized deploy — a payload from one repository mutating another tenant's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). The attack is repeatable against any victim commit whose sha the attacker can reproduce (all commits are candidates since git shas are always reproducible given the same tree/parent/author/message/timestamp), and is not limited to a single stack — every stack sharing that sha is affected.

### Likelihood Explanation
Preconditions: the attacker needs their own repository/organization already onboarded as a Shipit stack (a normal, low-privilege action in typical multi-tenant Shipit deployments, requiring no special Shipit or GitHub secret — only that they own a repo GitHub-App-installed for status/webhook delivery, which is standard self-service GitHub App installation on a repo they control). Reproducing an identical sha via cherry-pick is a genuine, well-known, zero-cost git operation requiring no secrets. No Shipit session, API token, or webhook secret of the victim's org is needed. This is fully repeatable and deterministic once the attacker knows the target sha (which is typically public).

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any other handler using a bare `Commit.where(sha:)`) to the repository that actually sent the webhook, e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })` or equivalently restrict to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, using the `stacks` helper already provided by `Handler` (scoped via `repository_name` from the payload). Additionally, consider enforcing global sha uniqueness is not the right fix (legitimately different stacks can share a sha if they are forks of the same code) — the correct fix is to always scope commit/status lookups by the webhook's own repository/stack.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or extending the existing handler test):
1. Create two `Stack` fixtures belonging to different repositories/organizations (`stack_one`, `stack_two`).
2. Create two `Commit` fixtures with an identical `sha` value (e.g. `"a" * 40`), one under `stack_one`, one under `stack_two`.
3. Assert precondition: `assert_equal 2, Shipit::Commit.where(sha: "a" * 40).count` — demonstrating the schema does not enforce global sha uniqueness (only the `(sha, stack_id)` composite unique index applies).
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly with a payload whose `repository.full_name` matches only `stack_one`'s repository and `sha` = `"a" * 40`, `state: "success"`.
5. Assert both commits received a new status: `assert_equal 1, commit_one.statuses.count` and, critically, `assert_equal 1, commit_two.statuses.count` even though the payload's repository never named `stack_two`'s repository — proving the cross-tenant write.

### Citations

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

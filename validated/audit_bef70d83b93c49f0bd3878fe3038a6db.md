### Title
Cross-tenant `status` webhook mutates commits across stacks/orgs without repository binding check - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filter on the payload's `repository.full_name`, and `Commit#add_status`'s `already_deployed = deployed?` guard is evaluated per-commit-row (`stack.last_deployed_commit.id >= id`), so the same sha can suppress hooks/CD in one stack while firing `deployable_status` and enqueuing `ContinuousDeliveryJob` in another. The commits schema explicitly supports multiple stacks holding a row with the identical sha (unique index is on `[sha, stack_id]`, not `sha` alone), so this is a real, reachable condition, not a theoretical one.

### Finding Description
The binding that should hold is: `payload.repository.full_name == commit.stack.repository.full_name` for every `commit` acted upon in `StatusHandler#process`. It does not hold.

- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This queries `Commit` globally by `sha` with no `stack`/`repository` scoping.
- `Commit#add_status` (`app/models/shipit/commit.rb:366-386`) computes `already_deployed = deployed?` (`stack.last_deployed_commit.id >= id`, `commit.rb:308-310`) per commit row and uses it to suppress `commit_status`/`deployable_status` hook emission; `Status#schedule_continuous_delivery` (`app/models/shipit/status.rb:42-44`) also runs per status creation and calls `Commit#schedule_continuous_delivery`, which is gated by `deployable?`/`stack.continuous_deployment?` (`commit.rb:281-287`), again evaluated independently per stack.
- The `commits` table's unique constraint is `[sha, stack_id]` (`test/dummy/db/schema.rb:85`, and migration `20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming the system is explicitly designed to allow the same `sha` to exist as separate rows under different `stack_id`s (and thus different `Repository`/org owners, since `Stack belongs_to Repository`).
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) authenticates the payload against the GitHub App/webhook secret belonging to the `repository.owner.login` named in the payload — i.e., it only proves the request came from (or was signed for) that one named repository/org. It does nothing to constrain which `Commit` rows the handler subsequently touches.

Exploit flow: an attacker who legitimately controls a repository/org tracked by Shipit (their own stack, own webhook secret) sends a `status` event naming their own repository and a `sha` value known to also be present (with different deploy status) in a victim stack belonging to a different org — realistic whenever repositories share commit history (forks, mirrors, shared upstream commits imported into multiple Shipit-tracked repos), since a git sha is a hash of commit content and is therefore identical across any repository containing that exact commit. The single, validly-signed webhook is processed once by `StatusHandler#process`, which updates every `Commit` row across every stack that shares that sha — including the victim's — silently, since neither `Commit`, `Status`, nor `add_status` check that the acting `commit.stack.repository.full_name` matches the payload's `repository.full_name`.

Existing guards do not close this gap: `verify_signature`/`verify_webhook_signature` only prove authenticity for the named repository's owner, not authorization to act on other repositories' data; `ExplicitParameters` only validates the payload schema (`sha`, `state`, etc.), not repository scoping; there is no `require_permission!`/`stacks` scope applied inside `StatusHandler#process`.

### Impact Explanation
A single validly-signed webhook write for repository A silently mutates `Commit`/`Status` state and triggers `Hook.emit(:deployable_status, ...)` plus `ContinuousDeliveryJob.perform_later(stack)` for an unrelated stack/repository B belonging to a different tenant/org — this is "a payload for one repository mutating another's stack, commit, task or team" and can produce "an unauthorized deploy," matching the Critical impact category. The blast radius is any pair of Shipit-tracked stacks (regardless of org) that happen to share a commit sha, which is common for forked/mirrored repositories or repos importing the same upstream history. It is repeatable: the attacker can retry with different shas known from public commit history to probe or trigger unrelated tenants' continuous delivery pipelines.

### Likelihood Explanation
Preconditions: (1) attacker must be able to produce a request that passes `verify_signature` for *some* organization named in the payload — trivially true if that organization is one the attacker legitimately owns/operates within the same shared Shipit installation, or if that organization's `webhook_secret` is unset (`verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, per `lib/shipit/github_app.rb:76-83`, and the docs list `webhook_secret` as "(optional)"); (2) a target stack in a different org must contain a `Commit` row with the identical `sha`, which happens naturally for forked/mirrored repositories tracked as separate Shipit stacks. Attacker cost is low: one crafted, self-signed webhook POST naming their own repository with a known shared sha. Given the schema is explicitly built to allow sha collisions across stacks, this is a design gap rather than a rare edge case, though it is contingent on the victim's stack actually sharing commit history with an attacker-controlled repository.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the repository named in the payload, e.g. join through `stack: :repository` and filter on `owner`/`name` matching `params.repository.owner.login` / `params.repository.name` (or the equivalent `full_name`), before calling `create_status_from_github!`. Apply the same repository-scoping check in any other handler that queries `Commit`/`Stack` by attacker-controlled identifiers alone (sha, branch) without verifying the payload's `repository.full_name` against the resolved records' owning `Repository`.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or extend `test/controllers/webhooks_controller_test.rb`):
1. Create `stack_a` (repository `org-a/repo`) with `commit_a` sha `SHA_X`, and a completed deploy so `commit_a.deployed?` is `true`.
2. Create `stack_b` (repository `org-b/repo`, different `Repository`/org, `continuous_deployment: true`) with `commit_b` sha `SHA_X` (same sha, no prior deploy), so `commit_b.deployed?` is `false`.
3. Build a single `status` payload: `{ sha: 'SHA_X', state: 'success', context: 'ci/travis', repository: { full_name: 'org-a/repo', owner: { login: 'org-a' } } }`, stub `verify_signature` to pass (as existing tests do via `GithubHook.any_instance.stubs(:verify_signature).returns(true)` / signature bypass).
4. POST to `/webhooks` with `X-Github-Event: status` and this payload.
5. Assert: `commit_a.reload` shows no `Hook.emit(:deployable_status, ...)` call and no `ContinuousDeliveryJob` enqueued for `stack_a` (already-deployed guard behaves as intended for the named repository).
6. Assert: `assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_b])` — i.e., `stack_b`, belonging to `org-b` and never named in the payload, receives a `ContinuousDeliveryJob` enqueue as a side effect of the same single webhook.
7. The test passes today (demonstrating the vulnerability) because `StatusHandler#process` applies `params` to every `Commit.where(sha: 'SHA_X')` row regardless of `stack.repository`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L308-310)
```ruby
    def deployed?
      stack.last_deployed_commit.id >= id
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/db/schema.rb (L79-87)
```ruby
    t.string "sha", limit: 40, null: false
    t.integer "stack_id", limit: 4, null: false
    t.datetime "updated_at"
    t.index ["author_id"], name: "index_commits_on_author_id"
    t.index ["committer_id"], name: "index_commits_on_committer_id"
    t.index ["created_at"], name: "index_commits_on_created_at"
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
    t.index ["stack_id"], name: "index_commits_on_stack_id"
  end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

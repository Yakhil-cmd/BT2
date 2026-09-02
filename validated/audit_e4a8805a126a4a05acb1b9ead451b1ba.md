### Title
`StatusHandler#process` writes commit statuses without scoping to the authenticating repository's stacks - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::Handler#stacks` is the only mechanism that binds a webhook's writes to the repository that authenticated the request via `Repository.from_github_repo_name(repository_name)`, and `PushHandler` correctly uses it. `StatusHandler#process` never calls `stacks`; it queries `Commit.where(sha: params.sha)` globally, so any commit sharing a sha across unrelated stacks gets mutated regardless of which repository sent the webhook.

### Finding Description
The binding that must hold for every handler is:

`mutated_commits == Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks&.commits&.where(sha: params.sha)`

`PushHandler#process` respects this: it scopes its `Stack` lookup through `stacks.not_archived.where(branch:)` [1](#0-0) , where `stacks` is defined as `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none` [2](#0-1) .

`StatusHandler#process`, however, does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This never invokes `self.stacks`, so `repository_name`/`Repository.from_github_repo_name` is completely unused for authorization scoping in this handler — any `Commit` row anywhere in the database with a matching `sha` is fetched and mutated, independent of which repository's webhook triggered the event.

`create_status_from_github!` calls `add_status`, which replicates the status, emits `commit_status`/`deployable_status` hooks, and — critically — calls `stack.schedule_merges` when the new status is `pending?` or `success?`, and `schedule_continuous_delivery` runs from `Commit#after_commit` callbacks when a commit is `deployable?` [4](#0-3) , [5](#0-4) . So this write is not read-only — it can influence merge/deploy eligibility of a stack the attacker does not control.

Existing guards do not catch this divergence:
- `verify_signature` in `WebhooksController` only validates the HMAC using the GitHub App secret keyed by `repository_owner` from the payload [6](#0-5) ; it does not verify that the `sha` belongs to the repository named in `payload['repository']`.
- `ExplicitParameters` schema in `StatusHandler` only validates types (`sha`, `state`, etc.) [7](#0-6) , not ownership.
- `drop_unhandled_event` and `check_if_ping` are unrelated to this issue.

Attack precondition: the attacker must be able to produce a genuinely-signed `status` webhook for a repository they legitimately own/administer (e.g., they can set commit statuses on their own repo via the GitHub API, and GitHub relays the real, correctly-signed webhook). If that repository shares any commit sha with a commit already persisted in another `Stack`/`Repository` (e.g., a shared fork/upstream history, common submodule, or coincidentally re-pushed commit), `Commit.where(sha:)` will match and mutate both records, even though the attacker never authenticated against the other repository.

### Impact Explanation
An attacker who legitimately controls a small repository can, via genuine (correctly signed) `status` webhooks for their own repo, cause Shipit to write status rows and trigger `stack.schedule_merges` / `schedule_continuous_delivery` for a `Commit` belonging to a completely different tenant's `Stack`, as long as a sha collision exists (most realistically via a shared/forked git history). This is a cross-tenant mutation of another repository's commit/stack state and can influence deploy/merge eligibility — matching the "Critical: a payload for one repository mutating another's stack, commit, task... or an unauthorized deploy" category. It is repeatable against any stack sharing commit shas with an attacker-controlled repo.

### Likelihood Explanation
Requires: (1) at least two `Repository`/`Stack` records in the same Shipit instance with overlapping commit history (a very common real-world scenario — forks, mirrors, shared upstream/vendor commits, monorepo splits); (2) the attacker owns/administers one of those repositories well enough to have GitHub send a genuinely-signed `status` webhook for it. No Shipit secrets, sessions, or API tokens are needed — the attacker relies entirely on GitHub's normal, legitimate signing of events for a repo they already control. Cost is low and the attack is repeatable for any sha they can arrange to match.

### Recommendation
Scope `StatusHandler#process` through `stacks.commits.where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`, mirroring `PushHandler`'s use of `stacks` so writes are confined to commits belonging to `Repository.from_github_repo_name(payload['repository']['full_name'])`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_scope_test.rb
class StatusHandlerScopeTest < ActiveSupport::TestCase
  test "StatusHandler#process never calls #stacks and mutates commits outside the authenticating repository's stacks" do
    repo_a = shipit_repositories(:shipit)                 # attacker-authenticated repo
    stack_a = repo_a.stacks.first
    repo_b = shipit_repositories(:cyclimse)                # unrelated repo/tenant
    stack_b = repo_b.stacks.first

    shared_sha = "a" * 40
    commit_a = stack_a.commits.create!(sha: shared_sha, message: "shared history")
    commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared history (fork)")

    payload = {
      "repository" => { "full_name" => repo_a.github_repo_name },
      "sha" => shared_sha,
      "state" => "success",
    }

    handler = Shipit::Webhooks::Handlers::StatusHandler.new(payload)

    # Binding under test: writes should be confined to repo_a.stacks
    scoped_shas = handler.send(:stacks).flat_map { |s| s.commits.where(sha: shared_sha).pluck(:id) }
    assert_not_includes scoped_shas, commit_b.id, "commit_b is outside repo_a's stacks"

    handler.expects(:stacks).never # StatusHandler#process does not use the scoping helper at all

    handler.process

    commit_b.reload
    assert commit_b.statuses.exists?(state: "success"),
      "commit belonging to an unrelated, unauthenticated repository/stack was mutated"
  end
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L365-386)
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

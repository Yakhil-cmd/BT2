### Title
Forged `status` webhook for a no-secret org updates commit status on **any** stack in the installation - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the targeted organization has no `webhook_secret` configured, so any request routed to that org's `verify_signature` check is treated as authentic. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with **no** repository/organization scoping, unlike sibling handlers, so the forged status can mutate a commit belonging to a completely different stack/organization than the one that "authenticated" the request.

### Finding Description
The broken binding is: *"a verified webhook for organization O should only be able to mutate state belonging to O's repositories."* In `WebhooksController#verify_signature` [1](#0-0) , `repository_owner` is taken straight from the attacker-controlled JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [2](#0-1) , and `Shipit.github(organization: repository_owner)` is looked up per that claimed value. `GitHubApp#verify_webhook_signature` then does:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [3](#0-2) 

If org `O` (attacker-chosen name in the body) has no `webhook_secret` configured, verification always passes regardless of signature — this is the documented precondition of the question ("org configured without webhook_secret ... accepted unconditionally").

Once past that gate, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This queries `Commit` **globally**, with no `stacks`/repository filter, unlike `PushHandler` (`stacks.not_archived.where(branch:)`) [5](#0-4)  or `CheckSuiteHandler` (`stacks.where(branch: ...).each { |stack| stack.commits.where(sha: ...) }`) [6](#0-5) , both of which scope to stacks belonging to the verified repository/org before touching commits. The `commits` table index is `(stack_id, sha)`, not a unique index on `sha` alone [7](#0-6) , confirming the same SHA can legitimately exist across multiple, unrelated stacks (e.g., a common base commit shared across forks/mirrors, or coincidental collision in a large installation), and `StatusHandler` will update `create_status_from_github!` for **all** of them.

`create_status_from_github!` calls `add_status`, which replicates the forged status, emits `Hook.emit(:commit_status, ...)`/`Hook.emit(:deployable_status, ...)`, and can call `stack.schedule_merges` if the forged state is `pending`/`success` [8](#0-7) . Because `deployable?` depends on statuses (`success? && !blocked?`) [9](#0-8) , a forged "success" status can make a commit on an unrelated victim stack `deployable?` and trigger continuous delivery via `schedule_continuous_delivery` [10](#0-9) .

Existing guards do not stop this: `verify_signature` only checks the org named in the attacker's own payload, not the org that owns the matched commit's stack; `StatusHandler`'s `ExplicitParameters` schema only validates types (`sha`, `state`, etc.), it does not constrain which repository the sha may belong to.

### Impact Explanation
An attacker who knows (or can enumerate/guess) a target commit SHA on a victim stack can forge a `status` webhook claiming to originate from any organization that has no `webhook_secret` configured (a configuration the attacker does not control but the question stipulates exists), and the forged status will be written against the victim's commit even though the victim's own org/repo is properly secured. This is a cross-tenant write: a payload that only "authenticated" as org `O` mutates commit-status state belonging to a stack under a different, properly-configured organization — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team," and can escalate into an unauthorized deploy via `schedule_continuous_delivery`/`schedule_merges`. It is repeatable for every SHA the attacker knows, against any stack in the installation, as long as at least one org in the multi-org config has no `webhook_secret`.

### Likelihood Explanation
Requires: (1) the Shipit instance configured with multiple GitHub orgs (`Shipit.github(organization: ...)`) where at least one has no `webhook_secret` set — an existing, documented configuration mode (see `config/secrets.development.example.yml`) [11](#0-10) ; and (2) attacker knowledge of a target commit SHA (obtainable from the public GitHub repo/commit history for open-source victim repos). No secrets, sessions, or privileged roles are needed — a plain unauthenticated `POST /webhooks` request suffices, as stated in the rules.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries `Commit`/`Stack` directly) to only the stacks belonging to the verified repository, mirroring `PushHandler`/`CheckSuiteHandler`'s use of the `stacks` scope (e.g., `stacks.where(...).each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`). Separately, treat "no webhook_secret configured" as a hard misconfiguration to reject rather than silently trust (`verify_webhook_signature` should not `return true unless webhook_secret`).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "forged status for no-secret org mutates a commit belonging to a different, secured stack" do
  victim_stack = shipit_stacks(:shipit) # belongs to org "shopify" with webhook_secret configured
  victim_commit = shipit_commits(:first)
  victim_commit.update!(sha: 'deadbeef' * 5)

  # Attacker claims org "unsecured-org" which has no webhook_secret configured in secrets.yml
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'unsecured-org' }, 'full_name' => 'unsecured-org/some-repo' }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  # No X-Hub-Signature needed / arbitrary signature accepted because unsecured-org has nil webhook_secret

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: forged_payload, as: :json
  end

  assert_equal 'success', victim_commit.reload.status.state
  # BEFORE fix: passes (bug) — commit belonging to "shopify" stack mutated by request that only
  # authenticated as "unsecured-org".
  # AFTER fix: StatusHandler should scope by stacks belonging to "unsecured-org"; victim_commit
  # (belonging to a "shopify"-owned stack) must remain unaffected -> assert_no_difference instead.
end
```

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-2)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** config/secrets.development.example.yml (L18-34)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
```

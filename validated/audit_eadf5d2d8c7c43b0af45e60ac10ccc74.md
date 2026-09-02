This confirms the vulnerability. `CheckSuiteHandler` and `PushHandler` both use the `Handler#stacks` helper, which scopes the query to `Repository.from_github_repo_name(repository_name)&.stacks` — restricting effects to the repository named in the payload [1](#0-0) . `StatusHandler#process`, however, queries `Commit.where(sha: params.sha)` directly with no repository/stack scoping at all [2](#0-1) .

### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes a `Status` to every `Commit` record in the entire Shipit database that shares the attacker-supplied `sha`, regardless of which repository the webhook actually originated from. Because `Commit#blocked?`/`#deployable?` consult exactly these `Status` rows, an attacker who controls a webhook for *any* repository containing a shared commit sha (e.g., a public fork sharing history with the victim's repository) can inject a `failure` status on a blocking context and freeze deploys on a stack it does not own.

### Finding Description
The broken binding: it should hold that `commit.stack.repository.full_name == payload['repository']['full_name']` for any `Status` created from a webhook, i.e., a status must only be attributed to commits belonging to the repository that authenticated the webhook. Instead, the code enforces only `commit.sha == payload['sha']`, with no repository equality check at all.

Path: `WebhooksController#create` parses the JSON body and dispatches to handlers matched by event type [3](#0-2) . `verify_signature` picks the GitHub App/secret to check based on `repository_owner` read straight from the same untrusted payload [4](#0-3) , so it validates that *some* legitimately configured organization/app sent the payload — the *attacker's own* organization, if the attacker's own repo/fork is a real Shipit-enrolled tenant that installed the app and legitimately triggers a real GitHub status webhook. It does not, and cannot, validate that the `sha` in the payload actually belongs to that repository's history in Shipit's own tables.

`StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
This is a global, unscoped lookup across the `commits` table — not filtered by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, unlike `PushHandler#process` (`stacks.not_archived.where(branch:)...`) [5](#0-4)  and `CheckSuiteHandler#process` (`stacks.where(branch: ...)`) [6](#0-5) , both of which correctly scope through the `Handler#stacks` helper [1](#0-0) .

`Commit#create_status_from_github!` writes a `Status` keyed to `commit.stack_id` (the victim stack's id, taken from the matched `Commit` row, not from the webhook payload) [7](#0-6) , and `Status.replicate_from_github!` persists `state`/`context` verbatim from the attacker-controlled payload [8](#0-7) .

`Status#blocking?` and `Commit#blocked?`/`#deployable?` then consume this attacker-written row: a status is `blocking?` if `!success? && commit.blocking_statuses.include?(context)` [9](#0-8) , and `Commit#blocked?` checks whether any older, undeployed commit in the stack has a `blocking?` status [10](#0-9) , feeding into `deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [11](#0-10) . `blocking_statuses` comes straight from the victim stack's own `cached_deploy_spec` (`ci.blocking`) [12](#0-11) , so the attacker does not even need to know the victim's blocking-context configuration in advance — they only need the sha, state, and context to line up, and the victim's own config does the rest.

Attack requires the attacker's status webhook to name a `sha` that also exists as a `Commit` row belonging to the victim's stack. The most direct real-world route is git history sharing (a public fork of the victim's repository shares old commit shas with the upstream), combined with the attacker's fork/org being an independently enrolled Shipit tenant (so a real, correctly-signed webhook is dispatched by GitHub when the attacker posts a status on their own fork's commit via the GitHub Status API, which they can legitimately do since they own the fork).

Existing guards do not stop this: `verify_signature` only proves the payload came from *some* legitimate, Shipit-known GitHub organization — it says nothing about which repository's commits should be affected [4](#0-3) ; `drop_unhandled_event` and `ExplicitParameters` schema in `StatusHandler` only validate presence/type of `sha`/`state`/`context`, not repository ownership [13](#0-12) ; there is no unique index or repository-scoped uniqueness constraint on `Commit#sha` preventing the same sha from resolving to unrelated stacks' commit rows.

### Impact Explanation
A single forged/legitimately-sent status webhook from an attacker-controlled repository can write a `Shipit::Status` row onto a commit belonging to a completely unrelated victim stack, and — if the context matches the victim's `ci.blocking` list and state is not `success` — flip `Commit#blocked?`/`#deployable?` for all newer commits in that stack, freezing continuous delivery for the victim's entire stack. This is a cross-repository/cross-tenant record write triggered by a payload that never authenticated for the victim's repository, matching the "payload for one repository mutating another's stack/commit" Critical category. It is repeatable against any victim commit sha the attacker can discover/share (e.g., via forking), and the blast radius spans every stack sharing Shipit's `commits` table (i.e., the whole multi-tenant instance), not just one victim.

### Likelihood Explanation
Preconditions: (1) the victim stack must have a `ci.blocking` context configured and a `Commit` row for the target sha (both common/default setups per the shipit_single fixture) [14](#0-13) ; (2) the attacker needs a `sha` value that also resolves to a `Commit` row owned by the victim — realistically via shared git history (forks) or any other means of the same sha being tracked under two different repositories/stacks in this Shipit instance; (3) the attacker's own repository/org must be an actual Shipit-enrolled tenant capable of generating a genuinely signed webhook (this is the main cost — it requires the attacker to control a repository that Shipit's GitHub App is installed on, which is plausible in any semi-open multi-tenant Shipit deployment where users can self-enroll their own forks/repos). No Shipit session, API token, or secret is required beyond owning a webhook-enrolled repository. The attack is fully repeatable and scriptable once the sha correspondence is found.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` and only update `Commit` rows belonging to those stacks' commits (e.g., `stacks.flat_map(&:commits).where(sha: params.sha)` or an equivalent `Commit.joins(:stack).where(stacks: { repository_id: repository.id }, sha: params.sha)`), rejecting/ignoring shas that don't belong to the requesting repository's own stacks.

### Proof of Concept
Minitest plan (model-level, no live GitHub, added to `test/models/shipit/webhooks/handlers/status_handler_test.rb` or similar — conceptually, per rules, actual file is out of scope for this analysis but described here):
1. Create `@victim_stack` with `cached_deploy_spec` containing `ci.blocking: ['soc/compliance']`, and two commits: `@victim_older` (undeployed, currently `success?`) and `@victim_newer` (currently `success?`, otherwise `deployable?`).
2. Create an unrelated `@attacker_repository`/`@attacker_stack` (different `full_name`, e.g. `attacker/repo`), with no relation to `@victim_stack`.
3. Build a status webhook payload: `{ 'sha' => @victim_older.sha, 'state' => 'failure', 'context' => 'soc/compliance', 'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature verification, since that is orthogonal to this binding — the point is that even a correctly-authenticated attacker-repo webhook reaches an unscoped commit lookup).
5. Assert: `@victim_older.reload.statuses.count == 1` and the new status's `context == 'soc/compliance'`, `state == 'failure'`.
6. Assert the equality violation: `refute_equal 'attacker/repo', @victim_older.stack.repository.full_name` (i.e., the status was written to a commit whose owning repository never matches the webhook's `repository.full_name`).
7. Assert the impact: `assert @victim_newer.reload.blocked?` and `refute @victim_newer.deployable?`, proving the attacker's payload—naming only its own unrelated repository—flipped `deployable?` on the victim's newer commit.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/status.rb (L23-33)
```ruby
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
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```

**File:** app/models/shipit/deploy_spec.rb (L202-204)
```ruby
    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```

**File:** test/fixtures/shipit/stacks.yml (L368-373)
```yaml
        }
      },
      "ci": {
        "blocking": ["soc/compliance"]
      }
    }
```

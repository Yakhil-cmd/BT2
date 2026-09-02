### Title
`StatusHandler#process` writes forged GitHub statuses to any commit sharing a SHA, cross-tenant, unguarded by `Commit#locked?` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits purely by `Commit.where(sha: params.sha)` with no scoping to the repository that actually emitted the webhook, so a `status` event delivered for one repository can create a `Status` row on a commit belonging to an entirely different stack/repository that merely shares the same SHA (e.g. via a fork sharing git history). `Commit#create_status_from_github!` performs this write unconditionally, with no check of `commit.locked?` or `stack.locked?`. Separately, `Commit#deployable?` does check `!locked?`, so for a commit that is individually locked, the downstream continuous-delivery trigger is blocked even though the forged `Status` row is persisted.

### Finding Description
The claimed binding is: `commit.locked? == true` should imply no write occurs to that commit via the status webhook path. Tracing the code shows this equality does **not** hold for the write itself, only for the deploy trigger:

- `app/controllers/shipit/webhooks_controller.rb` dispatches the `status` event to `Shipit::Webhooks.for_event('status')` after `verify_signature`, which only checks the HMAC against the webhook secret configured for `repository_owner` (the organization named in the payload) — it never validates that the payload's `repository.full_name` matches the stack that owns the target commit. [1](#0-0) 
- `StatusHandler#process` resolves target commits solely by SHA, with no repository/stack scoping at all: [2](#0-1) 
- `Commit#create_status_from_github!` performs the write unconditionally — no `locked?` or stack-ownership check exists in this method or in `add_status`: [3](#0-2) 
- Only the deploy-trigger side checks locking, in `Commit#deployable?`: [4](#0-3) 

Exploit flow: an attacker who owns/forks a repository sharing git history with a repository tracked by a Shipit stack (so some commit SHA is identical in both) causes GitHub to emit a legitimate, correctly-signed `status` webhook for their own repository (e.g. by pushing to their fork or calling the Statuses API on a repo they control, within an organization where Shipit's GitHub App is installed with broad repository access). Shipit's `verify_signature` accepts it because it is a real signature for that organization; `StatusHandler#process` then matches `Commit.where(sha: params.sha)`, which returns the victim stack's commit row too (same SHA, different stack), and creates a `Status` row on it — regardless of whether that commit or its stack is locked. This confirms the write-path binding is fully broken (cross-tenant `Status` creation succeeds unconditionally), while the deploy-trigger binding (`deployable?`) is intact for the specific case where the victim commit is individually locked, since `!locked?` correctly evaluates to `false` and `trigger_continuous_delivery` skips it.

### Impact Explanation
The impact is scoped to the write itself: an unauthenticated-w.r.t.-target-repository actor can inject arbitrary CI status data (`state`, `description`, `target_url`, `context`, `created_at`) onto a commit belonging to a stack/repository they do not control, as long as a SHA collision (realistically via shared git history/forks) exists. This is a cross-repository mutation of another tenant's `Commit`/`Status` records, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). For the specific locked-commit case examined here, the downstream unauthorized-deploy risk is mitigated by `Commit#deployable?`'s `!locked?` check, so no deploy/rollback is triggered by this particular forged status — but stacks/commits that are *not* individually locked remain exposed to the write feeding into `trigger_continuous_delivery` and potentially an unauthorized deploy.

### Likelihood Explanation
Requires: (1) a SHA shared between the attacker-reachable repository and the victim stack's tracked repository (achievable via forking, since forks retain identical commit SHAs for shared history), and (2) that repository being covered by a Shipit-trusted GitHub App installation (e.g., an "all repositories" install on an org, or the attacker having push/status-setting rights on a sibling repo in the same trusted org). Given these preconditions, the attack is repeatable at will against any commit sharing a SHA, requires no Shipit credentials, and does not require bypassing `verify_signature` since GitHub itself signs the webhook.

### Recommendation
Scope `StatusHandler#process` (and `refresh_statuses!`) to only update commits belonging to the stack whose `github_repo_name` matches the webhook payload's `repository.full_name`, e.g. filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repo_owner: ..., repo_name: ... })` instead of matching by SHA alone across the whole table.

### Proof of Concept
```ruby
# test/models/commits_test.rb (illustrative)
test "create_status_from_github! writes to a locked commit but deployable? blocks CD" do
  victim_commit = shipit_commits(:cyclimse_first)
  victim_commit.update!(locked: true)

  assert_difference '@stack.commits.first.statuses.count' do
    # simulate cross-tenant match: any Commit row with this sha gets the write
    Commit.where(sha: victim_commit.sha).each do |c|
      c.create_status_from_github!(OpenStruct.new(state: 'success', description: nil,
                                                    context: 'ci', target_url: nil, created_at: Time.now))
    end
  end

  assert victim_commit.reload.statuses.exists?(state: 'success') # write succeeded despite lock
  refute_predicate victim_commit, :deployable?                    # deploy-trigger still blocked

  assert_no_difference 'Deploy.count' do
    victim_commit.stack.trigger_continuous_delivery
  end
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

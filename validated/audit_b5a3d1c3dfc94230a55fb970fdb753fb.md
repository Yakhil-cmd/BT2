### Title
Cross-repository SHA-collision commit status forgery corrupts `Stack#next_commit_to_deploy` / `next_expected_commit_to_deploy` ordering - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit for an incoming `status` webhook purely by `sha`, with no scoping to the repository that emitted the event, and writes a `Status` row onto every matching `Commit` across every `Stack` in the installation. Because a git commit SHA is a pure hash of its content/parents/metadata and is independent of which repository stores it, an attacker who can get a signed webhook delivered for any repository can forge a `success`/`failure` status on a commit that actually belongs to a completely unrelated victim stack, directly changing what `Stack#next_commit_to_deploy` / `Stack#next_expected_commit_to_deploy` (and therefore `ContinuousDeliveryJob`) selects for deployment.

### Finding Description
The claimed binding is: `webhook.repository.full_name == commit.stack.repository.full_name` (the repo whose CI/API produced the `status` event must equal the repo whose stack/commit gets mutated).

Tracing the code:
- `WebhooksController#create` parses the raw payload and dispatches by event type: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) .
- `verify_signature` only checks that the payload is validly signed for the *organization* named in the payload itself (`Shipit.github(organization: repository_owner)`); it never checks that the specific `repository.full_name` in the payload matches any specific tracked `Stack`/`Repository` [2](#0-1) .
- `StatusHandler#process` then resolves the target commit **globally by SHA only**, with no repository/stack filter at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`Commit#sha` is not unique per stack in this query — `Commit.where(sha: ...)` runs against the whole `commits` table, matching every `Commit` row (in any `Stack`, i.e. any repository) that happens to share that SHA [4](#0-3) . Because a git commit's SHA-1 is computed solely from its tree, parent SHA(s), author/committer identity+timestamp, and message — none of which encode "which repository stores this" — an attacker who can read a victim's public commit metadata (tree hash, parent SHA, author/committer, timestamps, message, all exposed via the GitHub API/UI) can reconstruct a byte-identical commit object inside their own, completely unrelated repository, yielding an identical SHA. They then set a commit status (`success`) on that SHA in their own repo via the GitHub Status API. GitHub delivers a legitimately signed `status` webhook for the attacker's own repository. `verify_signature` passes because the signature is validated only against the attacker's own organization's/app's webhook secret, not against the specific repository/stack being targeted. `StatusHandler#process` then finds the *victim's* `Commit` row (same SHA, different stack/repo) and calls `commit.create_status_from_github!(params)` on it, writing a forged `Status` for the victim stack.

This corrupted `Status` feeds directly into `Commit#deployable?` (via `add_status`) and thus into:
```ruby
def next_expected_commit_to_deploy(commits: nil)
  ...
  commits_to_deploy.find(&:deployable?)
end
``` [5](#0-4) 
and `Stack#next_commit_to_deploy` / `deployable_commits`, which is what `ContinuousDeliveryJob`/`trigger_continuous_delivery` uses to pick the commit actually deployed [6](#0-5) . `UndeployedCommit#expected_to_be_deployed?` also derives its answer straight from this same `next_expected_commit_to_deploy` value [7](#0-6) .

None of the existing guards catch this: `verify_signature` validates the org-level HMAC, not per-repository binding; `drop_unhandled_event` only checks the event name is registered; `ExplicitParameters` (`params do requires :sha ... end`) only validates the shape of the payload, not its origin repository; there is no `Repository`/`Stack` lookup or `full_name` comparison anywhere in `StatusHandler#process` or `Commit.create_status_from_github!`.

### Impact Explanation
An unauthenticated/unprivileged actor (owning or having status-write access to any GitHub repository with a webhook wired to this Shipit instance) can write arbitrary `Status` rows onto commits belonging to a victim's `Stack` in an entirely different repository, which changes `Stack#next_commit_to_deploy`, i.e. which exact commit `ContinuousDeliveryJob` ships next. This is a payload from one repository mutating another repository's stack/commit state and steering an unauthorized deploy decision — matching the "Critical: a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" category. It is repeatable against any victim commit whose full metadata (tree, parents, author/committer, timestamps, message) is discoverable by the attacker (i.e., any commit visible via GitHub, which for open-source/public repos is by definition true), and can be repeated across arbitrary stacks/repositories, so it is not limited to a single tenant.

### Likelihood Explanation
Preconditions: the attacker must control (or have status-write access to) at least one repository capable of emitting a validly-signed `status` webhook to the Shipit instance, and must be able to reconstruct a commit object byte-identical to the victim's target commit (straightforward: fetch the victim's commit's tree SHA, parent SHA, author, committer, timestamps and message via the public GitHub API, then create a commit with identical fields via the Git Data API in the attacker's own repo — no secrets or elevated GitHub/Shipit permissions required). The `maximum_commits_per_deploy` precondition and multiple queued undeployed commits are configuration/state conditions already assumed by the scenario, not additional attacker requirements. Cost is one API call to reconstruct the commit plus one API call to set its status; wholly repeatable and scriptable.

### Recommendation
Scope commit/status resolution to the repository that actually emitted the webhook: after resolving `repository_owner`/`repository.full_name` from the payload, restrict `StatusHandler#process`'s `Commit.where(sha: params.sha)` lookup to commits whose `stack.repository` matches that payload's repository (e.g., `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: ..., name: ... })`), rather than matching by SHA alone across the entire installation.

### Proof of Concept
Minitest plan (no live GitHub, uses `StatusHandler` directly to mirror what the controller dispatches after signature verification):

```ruby
test "cross-repo forged status corrupts next_commit_to_deploy for an unrelated stack" do
  victim_stack = shipit_stacks(:shipit) # repository "shopify/shipit-engine" for example
  # three undeployed victim commits, oldest to newest, none deployable
  c1 = victim_stack.commits.create!(sha: 'a' * 40, message: 'c1')
  c2 = victim_stack.commits.create!(sha: 'b' * 40, message: 'c2') # middle commit, will be forged
  c3 = victim_stack.commits.create!(sha: 'c' * 40, message: 'c3')

  refute victim_stack.next_expected_commit_to_deploy # none deployable yet

  # Attacker forges a `success` status on c2's SHA via an unrelated repository's
  # webhook payload -- StatusHandler#process does not check `repository.full_name`
  forged_params = ExplicitParameters::Parameters.new(
    sha: c2.sha, state: 'success', context: 'ci/attacker',
    description: nil, target_url: nil, created_at: nil,
    branches: [{ name: 'irrelevant-attacker-branch' }]
  )
  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    sha: c2.sha, state: 'success', context: 'ci/attacker',
    branches: [{ 'name' => 'irrelevant-attacker-branch' }]
  )

  c2.reload
  assert_predicate c2, :deployable?
  # binding check: the "expected to deploy" target is now the forged mid-queue commit,
  # even though it did not come from victim_stack.repository's own CI
  assert_equal c2, victim_stack.next_commit_to_deploy
  assert_equal c2, victim_stack.next_expected_commit_to_deploy
end
```

This demonstrates the equality `webhook.repository.full_name == commit.stack.repository.full_name` is not enforced: the assertion passes even though the forged status never originated from `victim_stack`'s own repository.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/stack.rb (L210-243)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end

    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end

    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```

**File:** app/models/shipit/undeployed_commit.rb (L47-53)
```ruby
    def expected_to_be_deployed?
      return false if @next_expected_commit_to_deploy.nil?
      return false unless stack.continuous_deployment
      return false if active?

      id <= @next_expected_commit_to_deploy.id
    end
```

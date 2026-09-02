### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The binding the question assumes — "`last_deployed_commit` for stack X always corresponds to a commit whose deployability derived solely from stack X's own authenticated CI signals" — is broken, but not primarily by an ordering race with `Commit#detach_children!`/`Commit.lock_all`. It is broken upstream, in `Shipit::Webhooks::Handlers::StatusHandler#process`, which resolves target commits by a **global, repository-unscoped** SHA lookup, allowing a validly-signed webhook from an attacker-controlled repository/org to attach a CI status to a commit belonging to an unrelated stack.

### Finding Description
Binding claimed: `stack_X.last_deployed_commit.status_provenance == stack_X.own_repository.ci_signals`. i.e., any status that makes a commit `deployable?` for stack X must have been authenticated as coming from stack X's own GitHub repository.

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) verifies the HMAC using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-supplied JSON body (`params.dig('repository','owner','login')`). This only proves the payload was signed with the secret belonging to whatever organization the attacker names in the payload — it says nothing about which `Commit`/`Stack` the payload's `sha` will ultimately touch.
- `Shipit::Webhooks::Handlers::Handler` defines a `stacks` helper (app/models/shipit/webhooks/handlers/handler.rb:32-34) that properly scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, and `PushHandler` uses exactly this scoping (`stacks.not_archived.where(branch:)`, app/models/shipit/webhooks/handlers/push_handler.rb:12-17).
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) does **not** use `stacks` at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` across the entire database, matching by `sha` alone, with no `stack_id`/`repository` filter.

Root cause: any GitHub repository (including a public fork of a tracked repo) that shares commit history with a tracked stack will contain commits with byte-identical SHAs (git SHAs are content hashes of tree+parents+author+committer+message; a straight fork/clone reproduces them exactly). An attacker who:
1. Forks a public repository that Shipit already tracks as a stack (call it `victim/repo`), obtaining identical SHAs for shared history, and
2. Registers their own fork (`attacker/repo`) as a legitimate GitHub webhook target pointed at the Shipit host's `/webhooks` endpoint, configured with a webhook secret that they themselves control/know for their own org,

can send a `status` event whose `repository.full_name` is `attacker/repo` and whose `sha` is a SHA shared with `victim/repo`'s history. `verify_signature` passes because it only checks the signature against `attacker`'s own org secret — a secret the attacker legitimately possesses. `StatusHandler#process` then finds **every** `Commit` row with that `sha`, including the one that belongs to `victim/repo`'s stack, and calls `commit.create_status_from_github!(params)` on it, writing an attacker-controlled `state`/`description`/`context`/`target_url`/`created_at` Status row onto the victim stack's commit — a genuine cross-repository write with no authentication of the victim relationship.

This is independent of, and precedes, any race with `detach_children!`/`lock_all`: those mechanisms mark descendant commits `detached`/`locked` after a reset/force-push/revert is detected in the *tracked* repository's own sync job (`GithubSyncJob`), but `Commit#deployable?` (app/models/shipit/commit.rb:227-229) does not check `detached?`, and forged statuses land via a completely separate code path that never consults `detach_children!`/`lock_all` state at all. `Commit.reachable`/`.detached` filtering is applied only in `Stack#next_commit_to_deploy` (via `.reachable`), so a stale commit that hasn't yet been detached is fully exposed to continuous delivery once it (falsely) becomes `success?`.

Why existing guards fail: `verify_signature` authenticates "this payload came from someone who knows org O's secret," not "this payload's `sha` belongs to a repository tracked under org O." No model validation, `ExplicitParameters` schema, or controller-level check re-derives which `Stack`/`Repository` a `sha` may legitimately belong to before `create_status_from_github!` is called.

### Impact Explanation
An attacker who owns any repository can inject fabricated CI statuses (`success`, arbitrary `context`/`description`/`target_url`) onto commits of any other stack tracked by the same Shipit instance, as long as the target commit's SHA is reproducible (trivial for forks of public repos, or any commit an attacker can construct with a chosen but content-identical tree/parent/message/timestamp). If the victim stack has `continuous_deployment: true`, this can make a stale, reverted, or otherwise-unauthenticated commit appear `deployable?` and trigger `ContinuousDeliveryJob`/`trigger_deploy` for the victim's stack — an unauthorized deploy driven by a payload for one repository mutating another's commit/task state. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy." Blast radius: any stack on the instance whose repository shares commit history (via public fork) with a repository the attacker controls; repeatable per commit/per stack.

### Likelihood Explanation
Preconditions: attacker needs (a) their own repository registered as a stack/webhook target on the same Shipit instance (or any org configuration for which they can obtain a valid webhook secret — e.g., an org they legitimately control on a multi-tenant instance), and (b) a target commit SHA shared with a victim stack, which is free to obtain by forking any public tracked repository. No victim secrets, sessions, or team membership are required. Attacker cost is minimal: fork + configure webhook + POST a JSON payload. This is fully repeatable and requires no timing/race conditions, only the (already latent) unscoped query.

### Recommendation
Scope `StatusHandler#process` to the repository declared (and signature-verified) in the payload, matching the pattern used in `PushHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a status webhook can only affect commits belonging to stacks whose `Repository.from_github_repo_name` matches the payload's `repository.full_name` — the same repository whose secret was used to authenticate the request.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/webhooks/handlers/status_handler_test.rb`):
```ruby
test "status webhook does not affect commits belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit)              # repo shopify/shipit-engine
  shared_sha   = shipit_commits(:first).sha           # SHA belonging to victim_stack

  # Attacker's own repo, unrelated org, but same SHA present in DB
  # (simulating a forked commit history producing identical SHA)
  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } }
  }

  GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true) # attacker owns this org's secret legitimately

  assert_difference -> { victim_stack.commits.find_by(sha: shared_sha).statuses.count }, 1 do
    request.headers['X-Github-Event'] = 'status'
    post :create, body: attacker_payload.to_json, as: :json
  end
  # EXPECTED (post-fix): assert_no_difference instead — status must not attach
  # unless attacker/repo actually maps to victim_stack's Repository.
end
```
Second assertion tying to the question's continuous-delivery framing:
```ruby
test "forged cross-repo status can make a stale commit deployable and trigger a deploy" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  commit = shipit_commits(:fifth) # some undeployed commit, currently not success
  refute_predicate commit, :deployable?

  attacker_payload = {
    'sha' => commit.sha, 'state' => 'success', 'context' => 'ci/travis',
    'branches' => [{ 'name' => victim_stack.branch }],
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }
  GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true)

  assert_enqueued_with(job: ContinuousDeliveryJob) do
    request.headers['X-Github-Event'] = 'status'
    post :create, body: attacker_payload.to_json, as: :json
  end
  ContinuousDeliveryJob.new.perform(victim_stack)
  assert_equal commit, victim_stack.reload.last_deployed_commit
  # last_deployed_commit now corresponds to a commit whose "success" status
  # was never authenticated by victim_stack's own repository — binding broken.
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L239-245)
```ruby
    def children
      self.class.where(stack_id:).newer_than(self)
    end

    def detach_children!
      children.detach!
    end
```

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
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

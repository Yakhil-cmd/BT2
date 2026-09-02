This vulnerability is confirmed by the code and its contrast with sibling handlers.

### Title
`StatusHandler#process` writes commit statuses by bare SHA with no repository scoping, allowing cross-stack status injection - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `params.sha` via `Commit.where(sha: params.sha).each`, unlike every other handler in this engine, which scopes work through the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) defined in the base `Handler` class. Because `Commit.sha` is not unique per-repository at the database or query level, a webhook whose payload's `repository` field only determines *which org's signing key* is used for signature verification can still flip CI state for a commit belonging to a completely different stack/repository, as long as the two repos happen to share that SHA (e.g. via a fork).

### Finding Description
The broken binding: the invariant that should hold is `status.stack_id == Repository.from_github_repo_name(payload.repository.full_name).stacks (commit's owning stack)`, i.e. a status webhook should only ever mutate commits belonging to the stack(s) tied to the repository that emitted/signed it. Instead, the actual code is: [1](#0-0) 
which resolves `Commit.where(sha: params.sha)` — completely repository-agnostic — and calls `commit.create_status_from_github!(params)` for every matching row across the whole `commits` table, regardless of stack.

Compare this to the base `Handler` class, which provides a `stacks` helper explicitly meant to scope any handler's effects to the repository that authenticated the webhook: [2](#0-1) 
Other handlers (e.g. the `pull_request/*` handlers) use this `stacks` scoping; `StatusHandler` does not.

`WebhooksController#verify_signature` only verifies that the payload came from a GitHub App/org matching `repository_owner` in the payload — it does not, and cannot, prove that the SHA referenced belongs to that repository: [3](#0-2) 

Once a status lands on the wrong commit, `Commit#add_status` schedules merges whenever the new status is `pending` or `success`: [4](#0-3) 
and `enable_ci_on_stack`/`schedule_continuous_delivery` fire from `Status` creation itself: [5](#0-4) 

Exploit flow: the attacker forks the victim's public repository (fork preserves identical git object SHAs for shared history/commits). The attacker configures/owns the fork such that GitHub emits a genuinely-signed `status` webhook (signed with the credentials for the attacker's own org/repository) referencing a SHA that also exists, unmodified, in the victim's tracked stack. Because `StatusHandler` never checks `payload.dig('repository','full_name')` against the commit's `stack`, the status is applied to every `Commit` row with that SHA — including the one in the victim's stack requiring `ci/e2e`. If `merge_queue_enabled` is true on the victim stack, `Commit#add_status` triggers `stack.schedule_merges`, which can advance the merge queue and let `merge!` fire, or otherwise affect deploy/CI state, using data the attacker fully controls (`state`, `description`, `target_url`).

Existing guards do not catch this: `verify_signature` validates *who signed*, not *which stack the SHA belongs to*; `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, not repository ownership; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler#process` as there is in the base `Handler#stacks` method used elsewhere.

### Impact Explanation
A payload authenticated for one repository (the attacker's own fork/org) mutates commit/status/CI state for a stack belonging to an entirely different repository/tenant — this is a direct case of "a payload for one repository mutating another's stack, commit, task or team," matching the **Critical** category (unauthorized deploy/rollback/merge of attacker-controlled state). With `merge_queue_enabled: true`, a forged green `ci/e2e` status can push the merge queue forward and trigger `merge!`, an unauthorized merge action on the victim's stack. This is repeatable against any repository configuration that shares commit SHAs with an attacker-accessible repo (most commonly via forks of open-source projects tracked by Shipit).

### Likelihood Explanation
Preconditions: (1) attacker must own/control a repository (e.g. a fork) that is wired into Shipit's GitHub App/webhook configuration and can trigger genuinely-signed `status` webhooks (does not require knowledge of Shipit's webhook secret — GitHub signs it); (2) the SHA in question must be present, unmodified, in both the attacker's repo and the victim stack's commit history — realistic for forks of the same upstream, shared submodule commits, or vendored/cherry-picked commits; (3) the victim stack must require the same `context` (e.g. `ci/e2e`) and have `merge_queue_enabled: true`. Attacker cost is low (fork + set a commit status via the GitHub API on their own repo), and the action is repeatable against any stack sharing commit history with an attacker-controlled repository.

### Recommendation
Scope `StatusHandler#process` the same way other handlers do: resolve `stacks` from `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and restrict the `Commit` lookup to `commit.sha == params.sha AND commit.stack_id IN stacks.map(&:id)` (or `Commit.where(sha: params.sha, stack: stacks)`), rather than an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
```ruby
test "status handler does not update commits belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit) # merge_queue_enabled: true, requires 'ci/e2e'
  victim_stack.update!(merge_queue_enabled: true)
  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/e2e',
    'repository' => { 'full_name' => 'attacker/unrelated-fork' }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
end
```
Assert `victim_commit.reload.state` remains unchanged (equality: `commit.stack_id` resolved from `Repository.from_github_repo_name('attacker/unrelated-fork')` must NOT equal `victim_stack.id`), confirming the current code violates this and a fix restores it.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

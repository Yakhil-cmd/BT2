### Title
`StatusHandler#process` writes GitHub status to `Commit` rows matched only by bare `sha`, ignoring the authenticated repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching every `Commit` record in the database that shares the same `sha`, regardless of which `Stack`/`Repository` it belongs to. Since a valid webhook only proves the payload was signed for the organization named in `repository.owner.login`, but that verified identity is never used to filter which commits get the status applied, any signed status webhook for a SHA that is also present in another stack's commit history (e.g. via a fork sharing git history) will mutate that unrelated stack's CI state, including `blocked?`/`deployable?` when `blocking_statuses` is configured.

### Finding Description
The broken binding: intended invariant is `status.affected_commits == Commit.where(sha: sha, stack: Repository.from_github_repo_name(payload.repository.full_name).stacks)`, i.e. a status should only touch commits belonging to the repository that authenticated the webhook. The actual code implements `status.affected_commits == Commit.where(sha: sha)` with no stack/repository filter at all: [1](#0-0) 

Compare this with the base `Handler` class, which explicitly provides a `stacks` helper meant to scope processing to `Repository.from_github_repo_name(repository_name)&.stacks`: [2](#0-1)  `StatusHandler` never calls this helper, so the authenticated repository identity from the payload is discarded entirely for the purpose of locating the commit(s) to mutate.

`WebhooksController#verify_signature` only checks that the raw payload was HMAC-signed using the GitHub App secret associated with `repository_owner` (`params.dig('repository','owner','login')`, itself attacker-supplied JSON): [3](#0-2)  This only proves "some org's webhook secret produced this payload" — it does not restrict which `Commit` rows in the database the handler is allowed to touch. Because `Commit.sha` is not globally unique across stacks (two stacks tracking related git histories, e.g. a fork of a monitored repo, can contain rows with identical `sha`), an attacker who owns/controls a repository already onboarded into Shipit (and thus has a legitimate GitHub App webhook secret for their own org) can:

1. Fork or otherwise obtain history overlap with a victim repository so a specific commit SHA exists in both the attacker's stack and the victim's stack's `Commit` table.
2. Send a `status` webhook (`context: "ci/jenkins"`, `sha: <shared sha>`, `state: "success"` or `"failure"`) signed with their own org's GitHub App secret.
3. `StatusHandler#process` runs `Commit.where(sha: <shared sha])`, which returns Commit rows in *both* the attacker's own stack and the victim's stack, and calls `commit.create_status_from_github!(params)` on each, appending the forged status to the victim's commit's `statuses` association.

`Commit#blocked?` recomputes from `stack.commits.reachable...any?(&:blocking?)` [4](#0-3) , and `deployable?` depends directly on `blocked?` and `success?` [5](#0-4) , both of which are recalculated from `status`, which is rebuilt from the injected `statuses` records via `Status::Group.compact` [6](#0-5) . `add_status` also triggers `stack.schedule_merges` when the new status becomes pending/success [7](#0-6) , meaning the forged status can drive the victim stack's continuous delivery/merge machinery directly.

None of the existing guards prevent this: `verify_signature` validates payload authenticity for an org, not commit ownership; the `ExplicitParameters` schema on `StatusHandler` only validates types of `sha`/`state`/`context`, not their relationship to a specific repository; and there is no `stacks`/repository filter applied before the `Commit.where(sha:)` query.

### Impact Explanation
A signed webhook from one onboarded repository/org can write CI status records into `Commit` rows that belong to an unrelated stack, as long as the SHA collides (realistic for forks sharing git history, which is common on GitHub). This can flip `blocked?`/`deployable?` on the victim stack, force or block deploys, and trigger `stack.schedule_merges`, matching the "Critical: a payload for one repository mutating another's stack/commit" and "an unauthorized deploy/merge" categories in scope. The blast radius spans every stack whose `Commit` table happens to contain the colliding SHA, not limited to a single victim.

### Likelihood Explanation
Preconditions: the attacker needs a repository/org already onboarded to Shipit with a working GitHub App webhook secret (satisfied by the "attacker owns a repo that can emit webhooks" clause), and a SHA collision between their commit history and the victim stack's tracked commits — trivially achievable by forking the victim's repository (fork commits retain identical SHAs to the upstream commits until diverging), then referencing an un-diverged ancestor SHA. Victim stack needs `blocking_statuses` configured, which is a normal, common configuration. The attack is fully repeatable and requires only crafting an HTTP POST with a valid signature for the attacker's own org — no privileged access to the victim stack or Shipit itself is required.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to stacks under the repository that authenticated the webhook, mirroring the base `Handler#stacks` helper, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures the verified repository identity from the payload is the sole scope for which commits can be mutated.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, illustrative — not present in current suite):
```ruby
test "#process does not affect commits belonging to a different stack sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(deploy_spec: DeploySpec::FileSystem.new('', 'production')) # blocking_statuses: ['ci/jenkins']
  attacker_stack = create_stack(repository: create_repository(name: 'attacker/repo'))

  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit')
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'attacker commit')

  # Binding under test:
  # expected: Commit.where(sha: shared_sha) scoped to attacker_stack only
  # actual:   Commit.where(sha: shared_sha) returns both victim_commit and attacker_commit
  assert_equal false, victim_commit.blocked? # before

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/jenkins',
    'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } }
  }
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # assert both sides of the equality after: victim commit should NOT have received the status
  assert_empty victim_commit.statuses, "attacker webhook must not write statuses to a different stack's commit"
end
```
This test would fail against current `StatusHandler#process`, demonstrating cross-stack status injection.

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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

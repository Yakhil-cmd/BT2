### Title
Cross-repository status-webhook forgery lets an attacker mark a private-stack commit deployable via sha collision - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits by raw `sha` only, without scoping to the repository that sent the webhook, unlike `PushHandler` and `CheckSuiteHandler` which both use the `stacks` helper (scoped via `Repository.from_github_repo_name(repository_name)`) before touching any commit. This lets a validly-signed `status` webhook from *any* repository create a `Status` record on a `Commit` belonging to an unrelated `Stack`, as long as the sha matches - exactly the scenario described (a public/foreign repo forging CI success for a sha that also exists in a private mirror/fork's history).

### Finding Description
The broken binding is: `Status` rows attached to a private `Stack`'s `Commit` should only ever be derived from webhooks whose `payload.dig('repository','full_name')` maps (via `Repository.from_github_repo_name`) to that same `Stack`. This binding does not hold in `StatusHandler`: [1](#0-0) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

There is no `stacks`/`repository_name` filter at all, whereas the base `Handler` class explicitly provides that scoping primitive for this purpose: [2](#0-1) 

and it is used correctly by `PushHandler` (`stacks.not_archived.where(branch:)`) and `CheckSuiteHandler` (`stacks.where(branch: params.check_suite.head_branch)`), but not by `StatusHandler`.

`Commit#create_status_from_github!` then writes the status using the *pre-existing* `commit.stack_id` (not any stack derived from the payload's repository), i.e. `statuses.replicate_from_github!(stack_id, github_status)`, and this feeds directly into `Commit#deployable?` (`success? && !blocked?`) and `UndeployedCommit#deploy_disallowed?` (`!deployable? || !stack.deployable?`).

Exploit flow:
1. Attacker owns/controls a public repository whose GitHub organization/App installation shares the same webhook secret validated by `WebhooksController#verify_signature` (via `Shipit.github(organization: repository_owner)`), which is a realistic setup for a public upstream + private fork/mirror under one org.
2. Attacker triggers (or has GitHub emit) a `status` event for a commit sha that also exists, byte-for-byte, as a `Commit` row already ingested into the victim's private `Stack` (via prior sync of the shared git history).
3. `POST /webhooks` with `X-Github-Event: status` passes `verify_signature` (properly signed by GitHub for the attacker's own public repo) and is routed to `StatusHandler`.
4. `StatusHandler#process` finds the victim's private `Commit` row purely by `sha` (ignoring that the payload's `repository.full_name` is the attacker's unrelated public repo) and calls `commit.create_status_from_github!(params)`, writing a `success` `Status` scoped to the victim's private stack (`commit.stack_id`).
5. `Commit#deployable?` now returns true for that commit in the victim stack; `Api::DeploysController#create` (`require_permission :deploy, :stack`) accepts a deploy request for that sha, since `params.require_ci && !commit.deployable?` is false.

Existing guards do not stop this: `verify_signature` only authenticates that *some* GitHub org/app the attacker has repo access to sent a well-formed, correctly-signed webhook - it says nothing about which `Stack` the payload's data may affect. `drop_unhandled_event` and `ExplicitParameters` validate shape, not origin-scoping. `require_permission!` on the API controller only checks the caller may deploy to the named stack; it does not validate that the commit's CI status legitimately originated from that stack's own tracked repository.

### Impact Explanation
A `Status` record for a private repository's commit is written based on a webhook that legitimately originated from a different, attacker-controlled/public repository - a payload for one repository mutating another's commit/stack state. Combined with `Api::DeploysController#create`, this becomes an unauthorized deploy trigger: CI/security gates (`require_ci`, `deployable?`) can be bypassed for any commit whose sha the attacker can reproduce in a public/foreign repo and that coincidentally (via shared git history) also exists in the victim's private stack. This matches "Critical - unauthorized deploy" and "a payload for one repository mutating another's stack, commit, task or team." Blast radius: any tenant/stack in the Shipit instance is affected as soon as a matching sha exists as a `Commit` row anywhere, since `Commit.where(sha:)` has no stack scoping.

### Likelihood Explanation
Requires: (1) the attacker's repository is onboarded such that GitHub signs webhooks with a secret `verify_signature` accepts (realistic for orgs hosting both public upstream and private forks/mirrors under one GitHub App/org installation - exactly the scenario stated in the prompt); (2) a sha collision across repos, which is trivially achievable by intentionally sharing history (fork/mirror) rather than needing a hash collision; (3) the victim's private stack must have already synced that commit (so a `Commit` row exists). Given the stated precondition ("victim Stack tracks a private fork of a public upstream repo, sharing history"), this is straightforward and repeatable - the attacker can push arbitrary shas or manipulate their own repo's CI provider to emit `success` for any historical sha at will, and repeat against any stack it happens to intersect with.

### Recommendation
Scope `StatusHandler#process` to the requesting repository like `PushHandler`/`CheckSuiteHandler` do, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
so that a status webhook can only affect commits belonging to stacks whose tracked repository matches `payload.dig('repository', 'full_name')`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook from unrelated repository must not update a commit belonging to a different stack" do
  victim_stack = shipit_stacks(:private_fork_stack) # tracks e.g. "acme/private-mirror"
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared history commit", ...)
  victim_commit.statuses.destroy_all
  refute_predicate victim_commit.reload, :deployable? # left-hand side of the binding: false

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/forged",
    "repository" => { "full_name" => "attacker/public-repo", "owner" => { "login" => "attacker-org" } },
    "branches" => [{ "name" => "master" }],
  }

  Shipit::GithubApp.any_instance.stubs(:verify_webhook_signature).returns(true)
  post :create, params: payload, as: :json # X-Github-Event: status header set

  refute_predicate victim_commit.reload, :deployable?, "status from unrelated repo must not make victim commit deployable"
  # Currently FAILS: StatusHandler applies the status regardless of repository, making this assertion fail (commit becomes deployable? == true)
end
```
This demonstrates the binding `Status(commit, stack) derived only from payload.repository.full_name == stack.repository` does not hold, and that `Api::DeploysController#create` would subsequently accept a deploy for `victim_stack`/`shared_sha` once the forged status lands.

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

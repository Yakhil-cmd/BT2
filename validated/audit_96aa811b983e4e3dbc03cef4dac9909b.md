### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely `by sha` across the entire `Commits` table and writes a `Status` for every match, without ever checking that the matched commit's repository/stack corresponds to the repository named in the signed webhook payload. Since git commit SHAs are content-addressed and not repository-scoped, an attacker who owns any repository (and its own valid `webhook_secret`) can forge a `status` event for a well-known/reproducible SHA (e.g. the empty-tree hash `4b825dc642cb6eb9a060e54bf8d69288fbee4904`) and cause a `Shipit::Status` row to be written on an unrelated victim tenant's `Commit`, potentially unblocking that commit for deploy.

### Finding Description
The broken binding is: `repository_owning(Commit found by sha) == payload['repository']['full_name']`. This never holds in `StatusHandler`.

`Shipit::WebhooksController#verify_signature` resolves the GitHub App/org purely from the *payload's own* `repository.owner.login` (or `organization.login`) and verifies the signature against that org's `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves the attacker controls the repository they named in the payload — it says nothing about which `Commit`/`Stack` rows get mutated downstream.

`StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

This queries `Commit` globally by `sha`, with no `stacks`/`Repository` scoping at all. Compare this to the base `Handler` class, which provides exactly this scoping mechanism via `stacks`, resolving `Repository.from_github_repo_name(repository_name)` from `payload.dig('repository', 'full_name')`: [4](#0-3) 

And `PushHandler`, its sibling, correctly uses this scoping (`stacks.not_archived.where(branch:)...`) before acting: [5](#0-4) 

`StatusHandler` omits this scoping entirely, so `commit.create_status_from_github!(params)` fires for *every* `Commit` row in the database sharing that SHA, regardless of which `Stack`/`Repository`/organization it belongs to: [6](#0-5) 

**Exploit flow:** Attacker owns `attacker/empty-repo` with its own `webhook_secret`. A victim `Stack` in an unrelated `GithubHook`-owning org already has (or will have, e.g. via a rebase, cherry-pick, or empty commit that any repo can independently produce) a `Commit` row with `sha == '4b825dc642cb6eb9a060e54bf8d69288fbee4904'`. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a body `{sha: '4b82...', state: 'success', context: 'ci/travis', branches: [{name: 'master'}], repository: {full_name: 'attacker/empty-repo', owner: {login: 'attacker'}}}`, signed with `attacker`'s own valid `webhook_secret`. `verify_signature` passes because it only checks against `attacker`'s org. `StatusHandler.call` then finds the victim's `Commit` by SHA (since SHA collision/reuse across independent repos is trivial for empty or copied commits) and writes a forged `success` status onto it, with no reference to `attacker/empty-repo` at any point in the mutation.

No existing guard prevents this: `verify_signature` only authenticates the attacker's own claimed repository/org, not the target of the mutation; `ExplicitParameters` schema in `StatusHandler` validates field *types* only, not repository identity; there is no `stacks`/`Repository.from_github_repo_name` scoping call anywhere in `StatusHandler`.

### Impact Explanation
A payload cryptographically verified only for the attacker's own repository is used to write a `Shipit::Status` row onto a completely unrelated victim `Stack`'s `Commit`, without the victim's `webhook_secret` ever being consulted — this is a cross-tenant authentication/authorization bypass (payload for one repository mutating another's stack/commit). If the forged context matches one of the victim stack's required/blocking CI statuses, this can flip `commit.deployable?` to true (a `success` status can clear a blocking check), enabling an unauthorized deploy of a commit that never actually passed CI in the victim's repository. This is repeatable against any repository sharing a commit SHA with a victim (trivially engineered via identical empty commits, cherry-picked/rebased commits, or repository forks/mirrors that legitimately share history), and the attacker can retry with `state: 'success'`/`context` values matching any victim's specific CI check names, since `context` is attacker-controlled. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions are modest: the attacker needs only to own any GitHub repository and configure a `GithubHook` (with its own `webhook_secret`) for it in Shipit — the same low bar as any legitimate onboarded repository. They need a `Commit` sha that also exists in a victim's tracked history; the empty-tree hash `4b825dc642cb6eb9a060e54bf8d69288fbee4904` is universal to every git repo and will match if a victim ever has an empty commit tracked (common via merges/reverts), and more generally any commit an attacker can reproduce bit-for-bit (rebased/duplicated commits, forks) shares the same SHA. No GitHub session, Shipit credentials, or victim's `webhook_secret` are required — only the attacker's own secret and knowledge of the target `context` name (discoverable from the victim's public shipit.yml/CI config or public status checks on the victim's PRs). This is a low-cost, repeatable attack.

### Recommendation
Scope `StatusHandler#process` (and any other sha/identity-based handler) to the repository named in the verified payload, mirroring the pattern already used by `PushHandler`: resolve `stacks` from `payload.dig('repository', 'full_name')` and restrict the `Commit` lookup to commits belonging to those stacks, e.g. `Commit.where(sha: params.sha, stack_id: stacks.ids).each { |c| c.create_status_from_github!(params) }`, so that a commit is only updated if it belongs to a `Stack` whose `Repository` matches the authenticated payload's repository.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "status webhook signed for attacker repo must not write status on victim commit sharing sha" do
  # Setup: victim stack/commit in a different GithubHook-owning org
  victim_commit = shipit_commits(:first) # belongs to :shipit stack/org
  shared_sha = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
  victim_commit.update!(sha: shared_sha)

  # Attacker's own repo/hook with its own secret, verified independently
  attacker_repository_params = {
    'repository' => { 'full_name' => 'attacker/empty-repo', 'owner' => { 'login' => 'attacker' } }
  }
  body = {
    'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/travis',
    'branches' => [{ 'name' => 'master' }]
  }.merge(attacker_repository_params).to_json

  request.headers['X-Github-Event'] = 'status'
  # Signature verified using ONLY attacker's own webhook_secret via Shipit.github(organization: 'attacker')
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  assert_no_difference -> { victim_commit.statuses.count } do
    post :create, body:, as: :json
  end
  # FAILS today: victim_commit.statuses.count increases by 1 even though
  # the signature only proved control of 'attacker/empty-repo'.
end
```
Equality to assert on both sides: `repository_owning(victim_commit).full_name` ("shopify/shipit" or victim org) must never equal `payload['repository']['full_name']` ("attacker/empty-repo"), yet `StatusHandler#process` still mutates `victim_commit.statuses` — proving the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

### Title
StatusHandler mutates commits across tenants because `Commit.where(sha: params.sha)` is unscoped to the authenticated repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits globally by SHA and calls `create_status_from_github!` on every match, without ever filtering through the `stacks`/`repository_name` scope that `Handler` provides and that other handlers (`PushHandler`, `CheckSuiteHandler`) explicitly use. Since `verify_signature` only proves that the request was signed by the org named in the payload's own `repository.owner.login`/`organization.login`, and that org is fully attacker-controlled, an attacker can forge a CI status on a commit belonging to any other tenant's stack whenever a SHA collision exists between their repo and the victim's.

### Finding Description
The intended binding is: `organization whose webhook_secret verified this payload == organization owning every Commit row mutated by processing it`. `WebhooksController#verify_signature` computes `repository_owner` from the attacker-controlled JSON payload (`params.dig('repository', 'owner', 'login')`) and verifies the signature against `Shipit.github(organization: repository_owner)`'s secret [1](#0-0) [2](#0-1) . This only proves the payload was signed by the attacker's own registered organization — it says nothing about which `Commit` rows may be touched.

`Handler` exposes a `stacks` helper that scopes strictly to `Repository.from_github_repo_name(repository_name)` derived from the payload's `repository.full_name` [3](#0-2) . `PushHandler` and `CheckSuiteHandler` correctly use this scope before touching any `Stack`/`Commit` data [4](#0-3) [5](#0-4) .

`StatusHandler#process`, however, does not use `stacks` at all:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 

This is a global, cross-tenant `ActiveRecord` query with no join or filter on repository/owner. GitHub's `status` webhook payload does include a `repository` object, but `StatusHandler`'s `params` schema only declares `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` — it never uses `repository_name`/`stacks` to constrain the lookup [7](#0-6) .

Exploit flow: attacker registers/owns a GitHub org and repo with a Shipit webhook installed, obtains that org's legitimate `webhook_secret` (their own), and sends a signed `status` event naming a `sha` that happens to also exist as a `Commit` row in a different, unrelated stack (e.g., identical merge/empty commit, or a commit cherry-picked/mirrored from a shared upstream). `verify_signature` succeeds because it only authenticates against the attacker's own org. `StatusHandler#process` then finds and mutates *every* `Commit` row across all stacks sharing that SHA, including the victim's, via `commit.create_status_from_github!(params)`.

None of the listed guards prevent this: `verify_signature` authenticates per-payload-org, not per-mutated-commit; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape, not repository ownership; there is no `stacks`/`repository_name` filter anywhere in this handler.

### Impact Explanation
A successful forged `status` webhook writes a `Status` row on another tenant's `Commit` under the attacker's chosen `state`/`context`/`description`/`target_url`. Since `Stack#deployment_checks_passed?`/`deployable?` typically depend on the aggregated status of required contexts on the latest commit, this can flip an unrelated stack's deployability, letting an unrelated Shipit operator (unknowingly) deploy a commit that never actually passed CI, or block/spoof failure on a legitimate deploy — a cross-repository state write against a tenant that never authenticated the request. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any SHA collision the attacker can find or engineer (e.g., mirroring/forking a public upstream repo used by the victim, or crafting identical empty/merge commits).

### Likelihood Explanation
Precondition is a SHA collision between a commit in the attacker's own repo (tracked by their own Shipit-integrated org) and a commit in the victim's tracked stack. This is plausible in real-world scenarios: forks/mirrors of the same upstream repository, identical squash/merge commits, or empty commits sharing content and parent produce identical SHAs (git SHAs are content-addressed, not repo-addressed). No secrets are needed — the attacker only needs their own legitimate webhook installation, which they control by definition. This makes the attack low-cost, plausible, and repeatable at will against any repository whose commits become known to collide (or can be made to collide by cherry-picking/mirroring).

### Recommendation
Scope `StatusHandler#process` to the authenticated repository, mirroring `PushHandler`/`CheckSuiteHandler`, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or more efficiently, join through `Stack`'s repository association:
```ruby
Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each do |commit|
  commit.create_status_from_github!(params)
end
```
This ensures only commits belonging to stacks under the repository named in (and cryptographically bound to) the verified payload can be mutated.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks from different fixture orgs, e.g. `shipit_stacks(:shipit)` (repo `shopify/shipit-engine`) and `shipit_stacks(:soc)` (a different org/repo).
2. Create two `Commit` rows with the identical `sha` "deadbeef...", one under each stack.
3. Build a `status` webhook payload with `sha: "deadbeef..."`, `state: "success"`, and `repository.owner.login` set to the `soc` org (simulating attacker-owned repo whose webhook_secret signs the request).
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature verification, since that step is orthogonal to this bug — it only proves origin, not scope).
5. Assert `commit_under_soc.statuses.reload` contains the new forged status (expected).
6. Assert `commit_under_shipit.statuses.reload` — **also** contains the forged status, proving cross-tenant mutation, i.e. `commit_under_shipit.statuses.last.state == "success"` even though the `shipit` org's webhook secret never authenticated any request.
7. This demonstrates the binding "authenticating org == org owning mutated commit" is violated: both commits are mutated despite only one org's secret being used.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

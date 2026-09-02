### Title
`StatusHandler#process` matches commits by `sha` across *all* repositories, letting a webhook signed for one organization/repo flip `deployable?` on another organization's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with **no repository/stack scoping**, unlike the base `Handler#stacks` helper which correctly scopes lookups through `Repository.from_github_repo_name(repository_name)`. Because GitHub SHA-1 commit hashes are not globally unique to a single repository (two independent repos/forks that share history/a vendored commit will have `Commit` rows with the identical `sha` string but different `stack_id`), a legitimately signed `status` webhook for repo/org A will silently create a `Status` row (and can flip `deployable?`) on every other stack's `Commit` that happens to share that `sha`, including stacks belonging to a completely unrelated organization B.

### Finding Description
The broken binding the code is supposed to enforce is:
`Status.stack_id == the stack of the repository that authenticated (signed) this specific webhook payload`.

What actually happens:
1. `WebhooksController#verify_signature` authenticates the request using `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . This only proves the payload was signed by the GitHub App/org that matches `repository_owner` in the payload — it says nothing about which `Commit`/`Stack` rows may be touched.
2. `Handler` base class provides a correctly-scoped helper, `stacks`, that resolves only the stacks belonging to the repository named in the payload: `Repository.from_github_repo_name(repository_name)&.stacks` [3](#0-2) .
3. `StatusHandler#process` does **not** use this scoped helper. Instead it does a raw, unscoped lookup by `sha` alone:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 
4. `create_status_from_github!` → `add_status` creates a `Status` row tied to `commit.stack` (whatever stack that `Commit` row belongs to) and fires `deployable_status`/schedules continuous delivery [5](#0-4) .
5. `Commit#deployable?` becomes true purely from `success? && !blocked?` when `stack.ignore_ci?` is false [6](#0-5) .

Because step 3 skips repository scoping entirely, any `sha` collision across `Commit` rows belonging to different `Repository`/`Stack`/organization is sufficient to write a `Status` for a stack that never authenticated (or even received) this webhook. This is realistic in the documented multi-org deployment mode (`docs/setup.md`, "Using Multiple GitHub Applications") where one Shipit instance serves several organizations, each with its own webhook secret [7](#0-6) . An attacker who owns/forks a public repo that shares a commit (e.g., a vendored upstream sha) with a victim's tracked repository, and who has (or sets up) a genuine GitHub status webhook for their own fork/org, can post a real, correctly-signed `status` event for that shared sha. `verify_signature` passes because it only checks that the signature matches the attacker's own org's webhook secret — it never checks that the `repository`/`sha` in the payload actually maps back to a `Commit` under that same org's `Repository`.

Existing guards do not prevent this:
- `verify_signature` validates the HMAC against the org derived from the payload, not against the actual owner of the matched `Commit` rows.
- `drop_unhandled_event` / `ExplicitParameters` schema only validate the shape of `sha`/`state`, not repository ownership.
- The `Handler#stacks` scoping utility exists precisely for this purpose but `StatusHandler` doesn't call it.

### Impact Explanation
A `Status` record (and thus a `deployable?` transition, `deployable_status` hook emission, and scheduled continuous delivery/merges) gets written into a stack/commit that belongs to a repository the attacker never authenticated against and does not control. This is a cross-tenant, unauthorized write: "a payload for one repository mutating another's stack/commit," directly enabling an unauthorized deploy trigger (via `next_commit_to_deploy`/continuous deployment or an operator later clicking "Deploy" believing CI passed) on a repository the attacker has no relationship to. This is repeatable against any `sha` collision the attacker can arrange (fork a public repo tracked by a victim, since forks by definition share commit history/SHAs with the upstream). Matches Critical: "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy…trigger."

### Likelihood Explanation
Preconditions: the Shipit instance must track more than one `Repository`/`Stack` (potentially across different orgs, as in the documented multi-org config), and there must be a `Commit` row with an identical `sha` in both the attacker's own tracked repo and the victim's tracked repo — trivially achievable since forking a public repo preserves commit SHAs, and the victim only needs to have synced that upstream/shared commit into their stack (e.g., via a vendoring merge or a shared dependency commit). The attacker needs no privileges in Shipit itself — only the ability to have a repo/org with a real GitHub status webhook pointed at the shared Shipit host, which is the normal, legitimate setup for any onboarded repository. Attacker cost is low and the exploit is deterministic and repeatable for any shared sha.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to the repository named in the payload, using the same pattern as other handlers, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or query `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, ensuring the `repository_name` from the payload is the one used to resolve which `Stack`/`Commit` rows may be updated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_cross_tenant_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status webhook for one repository must not flip deployable? on an unrelated stack's commit sharing the same sha" do
          shared_sha = 'deadbeef' * 5

          repo_a = Repository.create!(owner: 'org-a', name: 'repo-a')
          stack_a = Stack.create!(repository: repo_a, environment: 'production', branch: 'master')
          commit_a = stack_a.commits.create!(sha: shared_sha, message: 'shared vendored commit',
                                              author: shipit_users(:walrus), committer: shipit_users(:walrus),
                                              authored_at: Time.now, committed_at: Time.now)

          repo_b = Repository.create!(owner: 'org-b-victim', name: 'repo-b')
          stack_b = Stack.create!(repository: repo_b, environment: 'production', branch: 'master')
          commit_b = stack_b.commits.create!(sha: shared_sha, message: 'shared vendored commit',
                                              author: shipit_users(:walrus), committer: shipit_users(:walrus),
                                              authored_at: Time.now, committed_at: Time.now)

          refute commit_a.deployable?
          refute commit_b.deployable?

          # Attacker only controls org-a's genuinely signed webhook payload, naming repo-a.
          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/travis',
            'branches' => [{ 'name' => 'master' }],
            'repository' => { 'full_name' => 'org-a/repo-a', 'owner' => { 'login' => 'org-a' } }
          }

          StatusHandler.call(payload)

          assert commit_a.reload.deployable?, "expected the authenticating org's own commit to become deployable"
          # BUG: unrelated victim stack's commit is also flipped, despite payload only naming org-a/repo-a
          assert commit_b.reload.deployable?, "unauthorized cross-tenant deployable? flip on victim stack"
        end
      end
    end
  end
end
```
This demonstrates that `StatusHandler.call` with a payload naming only `org-a/repo-a` still mutates `commit_b`'s status/`deployable?` under `stack_b` (`org-b-victim`), confirming the cross-tenant write via `Commit.where(sha: params.sha)` in [4](#0-3) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

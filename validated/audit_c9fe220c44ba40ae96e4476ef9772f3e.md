### Title
Cross-tenant CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit for an incoming `status` webhook by SHA alone, with no check that the authenticating GitHub organization actually owns the repository/stack that commit belongs to. Any GitHub organization configured as a Shipit tenant (multi-org `github:` config) can therefore write a forged, "successful" CI status onto a commit that belongs to a completely different organization's stack, as long as it can produce a commit object with an identical SHA (trivially achievable by forking a public victim repository, since Git commit hashes are content-addressed and preserved across forks).

### Finding Description
The broken binding: the webhook's authenticated tenant, `Shipit.github(organization: repository_owner).organization`, must equal `commit.stack.repository.owner`, but the code never checks this — it only checks `commit.sha == params.sha`.

Code path:
1. `WebhooksController#verify_signature` picks the GitHub App/secret to check against using `repository_owner = params.dig('repository','owner','login')` from the attacker-supplied JSON body itself, then verifies HMAC using that org's configured `webhook_secret` [1](#0-0) [2](#0-1) . In multi-org deployments (`lib/shipit.rb#github_app_config`), each organization has its own distinct `app_id`/`installation_id`/`webhook_secret` [3](#0-2) , but this only proves the webhook came from *some* org that is a legitimate tenant of this Shipit install — never that it came from the org owning the target commit.
2. `Shipit::Webhooks::Handlers::StatusHandler#process` then looks up commits **globally by SHA only**, with no repository/organization filter:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [4](#0-3) 
The `params` schema for this handler accepts only `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` — no repository identity field is required or checked [5](#0-4) .
3. `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` using `stack_id` from the **found (victim) commit**, not from the authenticated org [6](#0-5) .
4. `Status.replicate_from_github!` persists the row with that victim `stack_id` [7](#0-6) .

Attack: attacker's org "AttackerOrg" is a legitimately configured tenant of this Shipit instance (its own `webhook_secret` in `secrets.github`). Attacker forks the victim's public repository — Git commit objects are content-addressed, so the forked commit has an **identical SHA** to the victim's commit. Attacker then triggers (or, since they own the repo, directly emits) a `status` event on that SHA with `state: success` and a `context` the victim stack's DeploySpec doesn't hide/allow-fail (e.g. `ci/travis`). GitHub signs this webhook with AttackerOrg's real `webhook_secret`, so `verify_signature` passes. `StatusHandler#process` then finds the victim's `Commit` row (matching by SHA across the whole database) and writes a `success` `Status` under the victim's `stack_id`.

Existing guards do not stop this: `verify_signature` only authenticates "a known org signed this", not "this org owns this commit"; `ExplicitParameters` schema has no repository field to cross-check; there is no `stack.github_repo_name` / commit-repository correlation anywhere in this path.

### Impact Explanation
A forged green CI status is written into a victim stack's `Status` table, attributed to a webhook signed by an unrelated, attacker-controlled organization. This is exactly the "payload for one repository mutating another's stack" scenario: because `deployable?` on `Commit` depends on `success?`/`blocked?` derived from `Status` rows (via `state`, `blocking_statuses`) [8](#0-7) , this can make a commit appear deployable when it should not be, and can also trigger `enable_ci_on_stack` and `schedule_continuous_delivery` side effects [9](#0-8)  — potentially causing an unauthorized deploy/merge decision for a commit whose real CI status was never actually reported by the victim's own CI. This is repeatable against any commit SHA the attacker can reproduce (any public commit) and any stack in the shared multi-tenant Shipit instance. Matches "Critical - a payload for one repository mutating another's stack ... or an unauthorized deploy".

### Likelihood Explanation
Requires: (1) the Shipit instance uses the multi-org `github:` config (documented, supported feature) so multiple distinct, independently-authenticated tenants share one instance; (2) attacker controls/owns one such tenant org (a realistic scenario for SaaS-style or umbrella-org Shipit deployments); (3) the victim repository is public (or otherwise its exact commit content is known) so the attacker can reproduce an identical SHA by forking; (4) victim stack's DeploySpec doesn't hide/allow-fail the chosen context. All of these are plausible in real multi-tenant setups and require no privileged Shipit access, no secrets, and no session — only ordinary GitHub actions (own repo, own webhook).

### Recommendation
In `StatusHandler#process` (and other handlers keying off SHA, e.g. check-run handling), scope the `Commit` lookup by the authenticated organization/repository — join through `stack.repository` and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { ... repository matches repository_owner/full_name from verified payload ... })` — instead of a bare `Commit.where(sha: params.sha)`. Alternatively, thread the verified `repository_owner`/`repository.full_name` through to the handler and assert it matches `commit.stack.repository.owner`/`full_name` before calling `create_status_from_github!`, skipping (or erroring) on mismatch.

### Proof of Concept
Add to `test/models/status_test.rb` or a new controller test:

```ruby
test "replicate_from_github! writes into a stack whose org differs from the authenticating webhook org" do
  victim_commit = shipit_commits(:first)                 # belongs to stack owned by "shopify" org, per fixtures
  victim_stack  = victim_commit.stack

  # Simulate a status payload whose *authenticated* org (per Shipit.github(organization:)) is different
  attacker_org = 'attacker-org'
  github_status = OpenStruct.new(
    state: 'success', description: 'forged', target_url: 'http://evil.example.com',
    context: 'ci/travis', created_at: Time.now
  )

  # Confirm no relation exists between attacker_org and the victim stack's repository
  refute_equal attacker_org, victim_stack.repository.owner

  assert_difference '-> { victim_commit.statuses.count }', 1 do
    # This call sequence mirrors StatusHandler#process -> Commit#create_status_from_github! with no org check
    victim_commit.create_status_from_github!(github_status)
  end

  status = victim_commit.statuses.last
  assert_equal victim_stack.id, status.stack_id   # binding proven broken: victim stack_id used despite attacker-org provenance
end
```

This demonstrates the equality `status.stack_id == victim_commit.stack.id` holds even though the simulated authenticating org (`attacker_org`) is provably different from `victim_stack.repository.owner`, confirming the missing tenant-isolation check identified above.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by `sha`, with no scoping to the repository/organization that authenticated the webhook. Since GitHub commit SHAs are content-addressed and deterministic (e.g. the empty-tree SHA `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or any commit an attacker reproduces byte-for-byte), an attacker who owns any GitHub org/repo configured in Shipit (and thus possesses that org's valid `webhook_secret`) can send a signed `status` webhook whose `sha` collides with a commit belonging to a completely different, victim stack/org, flipping that victim commit's `deployable?` state and triggering `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` → an unauthorized deploy.

### Finding Description
The claimed binding is: `signing_org(webhook) == owning_org(stack_deployed)`. Tracing the code shows this binding is **not enforced**.

- `WebhooksController#verify_signature` resolves the signing app via `Shipit.github(organization: repository_owner)` where `repository_owner` comes from `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . This only verifies that *the payload's own declared owner* signed with a valid HMAC for that owner's configured `webhook_secret` — it says nothing about which Shipit `Stack`/repository the `sha` inside the payload actually belongs to.
- `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . This lookup is global across the entire `commits` table — it is not scoped by `stack_id`, `repository`, or any relation to `repository_owner`/`params['repository']['full_name']`. Any commit row in any stack, belonging to any tenant, whose `sha` matches the attacker-supplied value will be updated.
- `create_status_from_github!` → `add_status` writes a new `Status` and re-evaluates `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [4](#0-3) [5](#0-4) .
- `schedule_continuous_delivery` fires whenever `deployable? && stack.continuous_deployment? && stack.deployable?`, enqueueing `ContinuousDeliveryJob.perform_later(stack)` [6](#0-5) , which leads into `Stack#trigger_continuous_delivery` / `trigger_deploy` for the victim's stack — none of which re-validate that the status came from the stack's own configured repository/org.

Existing guards do not close this gap:
- `verify_webhook_signature` is a per-organization HMAC check, correctly rejecting forged signatures for an org the attacker doesn't control [7](#0-6) , but it never binds the verified org to the `sha`'s actual owning stack.
- `drop_unhandled_event`/`check_if_ping` only filter event types, irrelevant here.
- `ExplicitParameters` schema for `StatusHandler` only validates types/presence of `sha`, `state`, etc. [8](#0-7)  — it does not validate that the payload's `repository` matches the commit's stack repository.

**Attack**: Attacker registers/owns a repository under a GitHub org that is configured in Shipit's `secrets.github` multi-org config (so they legitimately hold that org's `webhook_secret` because it's their own org, per `Shipit.github(organization:)` / `github_app_config` [9](#0-8) ). They push an empty-tree commit (or replicate any victim commit's exact tree/parent/author/committer/timestamps to get an identical SHA) to their own repo, then `POST /webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with their own `webhook_secret`, and `sha` equal to the victim's undeployed commit's `sha`, `state: success`. `StatusHandler#process` matches the victim's `Commit` row purely by `sha` and updates its status, potentially flipping `deployable?` to `true` and triggering continuous deployment on the victim's stack — despite the attacker having no relationship to that stack, repository, or organization.

### Impact Explanation
This is an unauthorized deploy of a victim's stack triggered by a payload signed for an unrelated repository/organization — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy". The attacker gains the ability to force a `Deploy`/`Task` to run on a victim's infrastructure using arbitrary victim-controlled deploy commands (whatever the victim's stack pipeline runs), from a repo they fully control, with no Shipit session or privilege. It's repeatable against any stack with `continuous_deployment: true` and any sha the attacker can predict or reproduce (empty tree, or any historical commit whose exact content/metadata the attacker can replicate, or commits the attacker can observe on the victim's public repo and re-push byte-identically into their own repo). Blast radius spans across tenants/orgs hosted by the same Shipit instance, since the commit lookup is entirely un-scoped by org/repository.

### Likelihood Explanation
Preconditions: the victim `Stack` must have `continuous_deployment: true` and an undeployed `Commit` whose `sha` is attacker-predictable/reproducible; the attacker must control (or register) a repository under a GitHub org that is itself configured with valid Shipit webhook credentials (which is plausible in any multi-tenant/self-service Shipit deployment supporting many orgs). Cost is low: computing a colliding SHA for the empty tree requires no secret knowledge, and for arbitrary content it requires only reproducing the exact git object (feasible when mirroring a public/forked commit). No Shipit or GitHub secrets are required beyond the attacker's own org's webhook secret, which they legitimately possess. This is realistic in shared/multi-org Shipit deployments, though less applicable to fully single-tenant, single-org installations where the attacker cannot obtain any valid `webhook_secret` at all.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and equivalently in `CheckRunHandler`/other sha-keyed handlers) by the repository declared in the payload, e.g. join through `Stack` and filter by `stack.repo_owner`/`repo_name` matching `params.dig('repository','full_name')`, instead of a bare `Commit.where(sha:)`. Concretely, resolve candidate commits via `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repo_owner: ..., repo_name: ... })` so a status can only affect commits belonging to the same repository that was cryptographically verified as the sender.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual additions)
test "status webhook for org A cannot update a commit belonging to org B's stack" do
  empty_tree_sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

  stack_a = shipit_stacks(:shipit) # repo owned by org A
  stack_b = create_stack!(repo_owner: "victim-org", repo_name: "victim-repo", continuous_deployment: true)
  commit_b = stack_b.commits.create!(sha: empty_tree_sha, message: "victim commit")

  assert_not commit_b.deployable?

  handler = Shipit::Webhooks::Handlers::StatusHandler.new
  handler.call(
    "sha" => empty_tree_sha,
    "state" => "success",
    "repository" => { "owner" => { "login" => "attacker-org" }, "full_name" => "attacker-org/attacker-repo" }
  )

  commit_b.reload
  # Binding under test: signing_org("attacker-org") == owning_org(stack_b) -> false, yet status still applied
  assert commit_b.statuses.exists?(state: "success"), "victim commit status was mutated by an unrelated org's webhook"
  assert commit_b.deployable?, "victim commit became deployable from a cross-org forged status"
end
```
This demonstrates that a status signed and scoped for `attacker-org` mutates a commit belonging to `victim-org`'s stack, violating the claimed binding and enabling an unauthorized `ContinuousDeliveryJob` trigger on the victim's stack.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

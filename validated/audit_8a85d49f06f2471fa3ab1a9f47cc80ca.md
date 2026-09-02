### Title
Cross-organization webhook authentication confusion allows unauthorized deploy triggering and CI status forgery in multi-tenant Shipit — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment (`github` config keyed by organization name, each with its own GitHub App and `webhook_secret`), the `WebhooksController` selects which organization's secret to verify the incoming payload against using one field of the (still-unverified) JSON body, but the event handlers act on a *different* field of that same body to decide which repository/stack to mutate. Since the HMAC signature only proves "this exact raw body was signed with organization X's secret" and not "every field inside this body, in particular `repository.full_name`, belongs to organization X," an administrator of one tenant organization (who legitimately possesses their own org's webhook secret) can forge a payload whose `repository.owner.login` matches their own org (so their secret validates) while `repository.full_name` names a repository belonging to a completely different tenant organization on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp`/secret to validate against using `repository_owner`, derived from the raw, unauthenticated JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (including per-org `webhook_secret`) as documented for the "Using Multiple Github Applications" setup: [3](#0-2) [4](#0-3) 

`GitHubApp#verify_webhook_signature` HMACs the *entire raw request body* with the secret belonging to the organization chosen above: [5](#0-4) 

Crucially, this only proves the body was signed with organization X's secret — it does not prove that every embedded field (in particular `repository.full_name`, used to resolve the target `Repository`/`Stack`) actually belongs to organization X. Handlers resolve their target repository from a *different* payload field than the one used to select the verification secret: [6](#0-5) [7](#0-6) 

The `PushHandler` then triggers a `GithubSyncJob` (which appends commits and can trigger deploy cache/spec updates) for whatever stack that resolves to, using an attacker-supplied `after` SHA: [8](#0-7) [9](#0-8) 

The `StatusHandler` also acts purely on `params.sha` (a global lookup across `Commit`, not scoped to the org whose secret matched) to write CI/build statuses, which can be used to satisfy deploy-gating checks (`required_statuses`) on stacks belonging to a different org: [10](#0-9) 

The equality that should hold but doesn't:
`organization whose secret validated the signature == organization owning the repository/stack the handler mutates`

Before the attack: this equality is implicitly assumed true because in the common single-tenant deployment there is only one organization, so it trivially holds.

After the attack: in the documented multi-organization configuration, the attacker controls `OrgA`'s GitHub App and its `webhook_secret` (they set it up), and crafts a POST to `/webhooks` with `repository.owner.login = "OrgA"` (so `verify_signature` fetches `OrgA`'s secret and the HMAC they computed with that known secret validates), but sets `repository.full_name = "OrgB/target-repo"`. The equality breaks: the authenticated org (OrgA) differs from the org whose repository is written (OrgB).

### Impact Explanation
This is a direct instance of the rule's listed binding: "an organization that authenticated versus the repository that is written." An attacker who is merely a legitimate GitHub App owner/admin for one tenant organization on a shared Shipit instance can:
- Force `GithubSyncJob` to run for an arbitrary stack belonging to an unrelated organization, appending attacker-chosen commit SHAs and potentially triggering deploy-spec cache changes and downstream deploy behavior for that stack — an unauthorized action against a repository they have no access to (Critical: unauthorized deploy/rollback trigger).
- Forge commit statuses (`StatusHandler`) for arbitrary commit SHAs system-wide, since `Commit.where(sha: params.sha)` is not scoped to the org that authenticated, which can be used to falsify CI gating used to authorize deploys/merges on stacks in other organizations.

### Likelihood Explanation
Requires only that the target Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration) and that the attacker administers one of those organizations' GitHub App (thus knows that org's own `webhook_secret`, which they configured themselves — not a privileged Shipit credential and not access to the victim org). No Shipit session, `ApiClient` token, or victim-org credentials are needed.

### Recommendation
After verifying the HMAC signature for the organization derived from `repository_owner`/`organization.login`, re-validate that every repository-scoped field used by handlers (`repository.full_name`, `repository.owner.login`) is internally consistent with the organization whose secret validated the signature (e.g., assert `repository.full_name.split('/').first.casecmp?(repository_owner)`), rejecting the webhook with 422 otherwise.

### Proof of Concept
1. Configure Shipit with two tenant organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. As the administrator of `OrgA` (who set `OrgA`'s `webhook_secret` when creating their App), craft a JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha existing in OrgB/target-repo>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, validates the HMAC successfully (matches `OrgA`'s known secret).
6. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, which resolves `Repository.from_github_repo_name("OrgB/target-repo")` and enqueues `GithubSyncJob` for that stack with the attacker-chosen `after` SHA — an action against `OrgB`'s repository triggered solely by `OrgA`'s credentials.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

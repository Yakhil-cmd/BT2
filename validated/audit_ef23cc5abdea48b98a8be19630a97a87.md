This confirms the vulnerability: in a multi-organization deployment (`Shipit.github_organizations` with multiple entries in `secrets.github`), each organization has its own `webhook_secret` configured independently under its own key in `secrets.github` [1](#0-0) . The webhook signature is verified using the organization derived from the *webhook payload itself*, not from the repository that ends up being written to.

### Title
Webhook signature verified against attacker-chosen organization while the acted-upon repository is taken from the same unauthenticated payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to check the HMAC against based on `repository_owner`, which is read straight out of the untrusted JSON payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), before the signature itself has been validated. The payload's `repository.full_name` (used later by `Handler#repository_name` to resolve the `Stack`/`Repository`) is a separate, independently-attacker-controlled field within the same JSON body.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) . `Shipit.github(organization:)` looks up per-organization config (including a distinct `webhook_secret`) via `github_app_config` [4](#0-3) .

Once the signature check passes, `create` dispatches the same raw payload to handlers (e.g. `PushHandler`) which resolve the target `Stack` via `Repository.from_github_repo_name(repository_name)`, where `repository_name` is `payload.dig('repository', 'full_name')` [5](#0-4)  and `Repository.from_github_repo_name` splits this into `owner`/`name` to find the DB row [6](#0-5) .

`repository.owner.login` and `repository.full_name` are two independently-settable fields inside a single JSON body. In a multi-org Shipit installation, an actor who knows (or can obtain, e.g. through a compromised or lower-trust installation) the `webhook_secret` for organization A can craft a request whose `repository.owner.login` is `"orgA"` (satisfying signature verification against orgA's secret) while `repository.full_name` is `"orgB/some-repo"`. The signature is computed over the raw body and is *valid for that exact body* under orgA's secret — nothing ties the HMAC to a claim that the enclosed `repository.full_name` must equal `orgA/...`. The equality that should hold — organization whose secret authenticated the request == organization of the repository whose `Stack` state gets mutated — is not enforced. This breaks the binding "an organization that authenticated versus the repository that is written."

### Impact Explanation
Handlers triggered by webhooks perform mutating actions scoped to whatever `Repository`/`Stack` is resolved from the forged `full_name`, e.g. `PushHandler` calls `stack.sync_github(expected_head_sha:)` to enqueue `GithubSyncJob`, and `pull_request` handlers open/close merge requests and mutate `MergeRequest`/`Stack` state for repositories under org B, driven entirely by an org-A-signed payload [7](#0-6) . This lets an attacker who possesses (or leaks) a single organization's webhook secret in a multi-tenant Shipit deployment forge events that mutate/trigger state (syncs, merge-request lifecycle transitions) for stacks belonging to a completely different, unrelated organization — a cross-repository write across trust boundaries.

### Likelihood Explanation
Requires a multi-organization Shipit installation (`secrets.github` keyed by multiple orgs, as documented/supported by `Shipit.github_organizations`) and knowledge of one organization's `webhook_secret`. This is architecturally supported and documented (`docs/setup.md`, `config/secrets.development.shopify.yml` show the multi-org format) [1](#0-0) , but exploitation depends on obtaining a webhook secret for at least one tenant org, which is a real but non-trivial prerequisite.

### Recommendation
After successfully verifying the signature for `repository_owner`, re-derive the target repository/stack strictly from a value cryptographically bound to the same organization, or explicitly require that `repository.full_name`'s owner segment matches `repository_owner`/the verified organization before dispatching to handlers. Reject the webhook if the two disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` in `secrets.github` [1](#0-0) .
2. Craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` and POST to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner == "orgA"`, fetches orgA's `GitHubApp`, and the HMAC validates successfully [2](#0-1) .
5. `create` dispatches to `PushHandler`, which resolves the `Repository`/`Stack` via `full_name == "orgB/target-repo"` [5](#0-4) [6](#0-5)  and triggers `sync_github` on org B's stack — despite the request only being authenticated for org A.

### Citations

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

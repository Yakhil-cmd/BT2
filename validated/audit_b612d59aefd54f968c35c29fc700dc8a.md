Based on my analysis, I found the analogous binding-mismatch vulnerability.

### Title
Signature verification is keyed on `repository.owner.login`, but the sync/write path trusts a separate unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
The ERC-4337 bug class described is: a component of a signed/validated value is trusted for one decision (which key validated it) while a *different, unauthenticated* component of the same payload is trusted for the actual state-changing action, letting the two "views" of the data diverge. In `WebhooksController`, the field used to select which GitHub App/secret validates the HMAC (`repository.owner.login`, via `repository_owner`) is a *different* JSON field than the one later used by the handlers to decide which `Repository`/`Stack` gets synchronized (`repository.full_name`).

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret` used to validate `X-Hub-Signature`) purely from `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (or falls back to `organization.login`): [1](#0-0) [2](#0-1) 

Once the signature check passes, the raw parsed payload (not just the verified "owner" field) is handed unmodified to every registered handler: [3](#0-2) 

Handlers such as `PushHandler` then resolve which `Stack`s to write to using an entirely different field, `repository.full_name`, via `Handler#stacks`/`Handler#repository_name`: [4](#0-3) [5](#0-4) 

In the multi-organization configuration (`Shipit.github_app_config`/`Shipit.github`), each organization has its own independent `webhook_secret`: [6](#0-5) 

This reproduces the ERC-4337 aggregator problem structurally: `isFailed()`/`intersect()` inspected one packed bit-range (aggregator) to make a validity decision while a *different* bit-range was later relied upon for the actual outcome, letting attacker-influenced data diverge between the "checked" and "used" views. Here, the "checked" view is `repository.owner.login` (picks the secret) and the "used" view is `repository.full_name` (picks the repository/stack that is written to). Because GitHub webhook payloads are attacker-influenced content generated from repository metadata that the pushing account fully controls (e.g., a repository named `attacker-org/victim-shipit-target` or a renamed/transferred repository whose `owner.login` no longer matches its `full_name` prefix, or a fork/organization webhook relationship where the `organization.login` fallback differs from the pushed repository), a webhook validly signed with organization A's `webhook_secret` can carry a `repository.full_name` pointing at a stack that Shipit associates with organization B's repository. `verify_signature` only proves "this body was signed with organization A's secret" — it does not prove "the repository named in this body belongs to organization A."

### Impact Explanation
If exploitable, this allows a webhook that is validly authenticated for one organization/repository to trigger `GithubSyncJob`/`stack.sync_github` writes (commit ingestion, `mark_as_accessible!`/`mark_as_inaccessible!`, spec cache invalidation) against a `Stack` belonging to a *different* repository than the one whose secret was used to sign the request. This is a cross-repository write via a trust binding that is checked on one field but acted on another — matching the required "cross-repository writes" impact bucket.

### Likelihood Explanation
This requires the multi-organization GitHub App configuration (`secrets.github` keyed by organization) to be in use, and requires an attacker who controls a repository/organization with its own legitimately configured Shipit webhook (i.e., is an authorized GitHub App installer for *some* org known to Shipit), then crafts or transfers a repository whose `full_name` collides with a `Stack` tracked under a different, victim organization. This is a real but non-trivial precondition (needs control of at least one legitimately-configured organization's webhook and knowledge/matching of a target repository's `full_name`), making likelihood low-to-moderate but the binding mismatch is concretely present in the code as written.

### Recommendation
`verify_signature` and the downstream handlers must be bound to the *same* field. Either:
1. Verify the signature using the organization derived from `repository.full_name`'s owner segment (not `repository.owner.login`/`organization.login`), or
2. After signature verification, explicitly assert that `repository.owner.login` (the field used to pick the secret) matches the owner segment of `repository.full_name` (the field used to pick the `Stack`) before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit in multi-org mode with two organizations, `org-a` and `org-b`, each with a distinct GitHub App and `webhook_secret` (per `lib/shipit.rb#github_app_config`).
2. As an authorized installer/owner of `org-a`, arrange (e.g., via a repository rename/transfer sequence, or a crafted payload from an app installed with delivery access to shape `repository.full_name`) a push event whose JSON body has `repository.owner.login = "org-a"` but `repository.full_name = "org-b/victim-repo"`.
3. Sign the exact raw body with `org-a`'s `webhook_secret` and POST to `/webhooks` with header `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and validates successfully because the signature does correspond to `org-a`'s secret.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and enqueues `GithubSyncJob` for `org-b`'s stack, causing a cross-organization/cross-repository write despite the signature only proving authenticity for `org-a`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

### Title
Webhook signature verification keys off attacker-controlled `repository.owner.login`, decoupling the authenticated organization from the repository the payload mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to verify the HMAC against using a field taken from the still-unverified JSON body, while every event handler resolves the actual `Repository`/`Stack` to mutate using a *different* field (`repository.full_name`) from that same unverified body. In a multi-organization deployment (the supported `secrets.github.<org>` schema), this breaks the binding "organization whose secret authenticated the request" == "repository the handler writes to."

### Finding Description
`verify_signature` derives the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up that organization's config (including its own `webhook_secret`) via `github_app_config`, independent from any other organization's secret: [3](#0-2) 

`GitHubApp#verify_webhook_signature` uses whatever secret was resolved for that organization, and — critically — **returns `true` unconditionally when that organization has no `webhook_secret` configured** (a supported, documented configuration, e.g. `webhook_secret: nil` in `test/dummy/config/secrets_double_github_app.yml`): [4](#0-3) 

Once the request passes (or is exempted from) that check, every webhook handler ignores `repository.owner.login` entirely and instead resolves the target `Repository`/`Stack` from `repository.full_name` in the same JSON body: [5](#0-4) [6](#0-5) [7](#0-6) 

The equality that should hold is:
`organization used to select/verify the webhook_secret` == `organization that owns the repository the handler subsequently writes to`

It does not hold: the two lookups use two independent, both attacker-supplied JSON fields (`repository.owner.login` vs `repository.full_name`). An attacker can send a single JSON body where `repository.owner.login` names an organization configured with **no `webhook_secret`** (so `verify_webhook_signature` short-circuits to `true` for *any* payload/signature, including none), while `repository.full_name` names a completely different, unrelated repository belonging to a different, properly-secured organization also connected to this Shipit instance.

### Impact Explanation
This yields unauthenticated cross-organization/cross-repository writes into Shipit's own data model and workflow triggers:
- `PushHandler` enqueues `sync_github`/`GithubSyncJob` for any stack under the forged `repository.full_name`, poisoning Shipit's view of the target repo's HEAD.
- Pull-request handlers (`opened_handler`, `labeled_handler`, `reopened_handler`, `closed_handler`, etc.) can archive/unarchive review stacks, or mutate `PullRequest` records, for a target repository the attacker does not control, based purely on the forged `full_name`.
- Because none of this requires the attacker to know any of the excluded secrets (`webhook_secret`, `api_clients_secret`, GitHub App private key, an `ApiClient` token, or a Shipit session) — it only requires that *some* organization in the multi-tenant `secrets.github` config be provisioned without a `webhook_secret`, which is an explicitly supported configuration — this crosses the "cross-repository writes" bar for unprivileged attackers.

### Likelihood Explanation
Likelihood depends on the deployment having at least one organization with `webhook_secret` unset among several configured organizations (documented/supported via the multi-org `secrets.github.<org>` schema and exercised in `test/dummy/config/secrets_double_github_app.yml`). Where that precondition holds, exploitation requires nothing more than a single unauthenticated POST to `/webhooks` with a crafted JSON body — no signature, no header manipulation tricks, no credential access.

### Recommendation
Bind the two lookups together: after resolving `repository.owner.login` to select the verifying `GitHubApp`, re-derive/validate that the resolved organization actually matches the owner segment of `repository.full_name` before dispatching to handlers (or, simpler, verify the signature using the secret belonging to the organization that owns the resolved `Repository` record, not a payload-selected one). Additionally, treat "no `webhook_secret` configured for org X" as authorizing only events whose `repository.full_name` also belongs to org X, never as a blanket bypass for arbitrary repositories.

### Proof of Concept
1. Shipit is configured with two organizations, e.g. `OrgSecured` (has `webhook_secret` set) and `OrgOpen` (no `webhook_secret`, matching the supported schema shown in `test/dummy/config/secrets_double_github_app.yml`), both of which have repositories tracked as Shipit stacks.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, and a JSON body:
```json
{
  "repository": { "owner": { "login": "OrgOpen" }, "full_name": "OrgSecured/target-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. `verify_signature` computes `repository_owner = "OrgOpen"`, loads `OrgOpen`'s `GitHubApp` (no `webhook_secret`), and `verify_webhook_signature` returns `true` unconditionally [8](#0-7) .
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgSecured/target-repo")` [9](#0-8)  and enqueues a sync for `OrgSecured/target-repo` with an attacker-chosen `expected_head_sha`, despite the request never being authenticated for `OrgSecured`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

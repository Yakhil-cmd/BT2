### Title
Webhook signature verification is keyed on an attacker-controlled `repository.owner.login` field that is decoupled from the `repository.full_name` actually acted upon by handlers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub organization's `webhook_secret` to validate the HMAC against by reading `repository_owner` straight out of the unauthenticated JSON body, while every `Webhooks::Handlers::Handler` subclass resolves the `Repository`/`Stack` to act on from a *different* field in that same unauthenticated body: `repository.full_name`. The organization whose secret authenticates the request is never bound to the repository that is written to.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` computes the signing organization purely from the request body, before any authentication has occurred: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up that organization's config and instantiates a `GitHubApp` for it: [3](#0-2) 

`GitHubApp#verify_webhook_signature` then contains an explicit bypass when that organization has no `webhook_secret` configured: [4](#0-3) 

Note `return true unless webhook_secret` - if the org key chosen by the attacker-controlled `repository_owner` field maps to an org whose `webhook_secret` is blank/nil (a configuration explicitly shown as valid in this engine's own `config/secrets.development.shopify.yml`, which sets `webhook_secret: # nil`), the signature check passes unconditionally regardless of the actual `X-Hub-Signature` header content. [5](#0-4) 

Once past that check, `WebhooksController#create` dispatches the *entire unauthenticated payload* to handlers: [6](#0-5) 

Every handler resolves its target `Repository`/`Stack` from `repository.full_name`, a field wholly independent of `repository.owner.login` used for the auth check: [7](#0-6) [8](#0-7) [9](#0-8) 

`Repository.from_github_repo_name` performs a plain, unauthenticated string lookup unrelated to whichever org key satisfied `verify_signature`: [10](#0-9) 

**The broken binding, stated as an equality that should hold but doesn't:**
`organization authenticated by verify_signature (repository_owner)` == `owner of the repository/stack actually written to by the handler (repository.full_name)`.

Before a PR fixing this: the two sides are never compared; the org key is attacker-chosen from the body, and any org in the Shipit config with an unset `webhook_secret` becomes a universal signature bypass for *every* stack tracked by the Shipit instance, not just that org's own repos.

### Impact Explanation
This maps to the "Critical - unauthorized deploy/merge" and "authentication bypass" categories. Concretely, an unauthenticated attacker who knows (a) that some org configured in the Shipit instance has no `webhook_secret` set, and (b) the `owner/name` of a victim repository tracked by Shipit, can:
- Send `X-Github-Event: pull_request` with `action: opened`, `repository.full_name: "victim-org/victim-repo"`, `repository.owner.login: "<org-with-no-secret>"`, and attacker-chosen `pull_request.head.sha`/`ref`. If `review_stacks_enabled` is on for that repository, `OpenedHandler` calls `ReviewStackAdapter#find_or_create!`, which enqueues `ReviewStackProvisioningQueue.add(stack)` — triggering a real deploy/provision of attacker-chosen ref/sha on the deploy host, i.e., an **unauthorized deploy**.
- Send `X-Github-Event: push` with a forged `after` SHA to force `PushHandler` to call `stack.sync_github(expected_head_sha:)` on any tracked stack, manipulating Shipit's perceived deploy state.
- Forge `membership` events to add/remove arbitrary users to/from `Shipit.github_teams`-backed teams, escalating authorization (`membership_handler.rb`, confirmed reachable through the same `verify_signature` gate in `webhooks_controller_test.rb`).

The severity is amplified because the misconfiguration required (one org lacking `webhook_secret`) is explicitly modeled as a supported state in the engine's own sample config, and the code never re-validates that the authenticated org actually owns the repository being modified.

### Likelihood Explanation
Requires no credentials, no session, and no GitHub App private key — only knowledge that at least one configured Shipit GitHub org lacks a `webhook_secret` (undetectable from outside except by trial, since a wrong org name yields a distinguishable 422 `GithubOrganizationUnknown` versus an accepted request). Multi-org Shipit deployments where organizations are onboarded incrementally (some without webhook integration configured yet) are a realistic, silent way to hit this. Likelihood is moderate-to-high in any multi-tenant Shipit deployment.

### Recommendation
- In `GitHubApp#verify_webhook_signature`, never treat an absent `webhook_secret` as "verified" (`return true unless webhook_secret` should instead fail closed, or Shipit should refuse to register a GitHub org config without a webhook secret).
- Bind the authenticated organization to the object actually mutated: after selecting `github_app` by `repository_owner`, verify that `repository.owner.login` (or `organization.login`) matches the `owner` of the `Repository`/`Stack` resolved from `repository.full_name` before invoking handlers, rejecting mismatches.
- Add an application boot-time check that logs/fails if any configured GitHub org is missing a `webhook_secret`.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `victim-org` (fully configured, tracks `victim-org/victim-repo` with `review_stacks_enabled: true`) and `empty-org` (configured with `webhook_secret: nil`, as shown in `config/secrets.development.shopify.yml`).
2. POST to the webhooks endpoint with header `X-Github-Event: pull_request` and no valid `X-Hub-Signature` (or an arbitrary garbage value):
```json
{
  "action": "opened",
  "number": 1337,
  "repository": {"owner": {"login": "empty-org"}, "full_name": "victim-org/victim-repo"},
  "pull_request": {
    "id": 1, "number": 1337, "url": "https://x", "title": "x", "state": "open",
    "additions": 1, "deletions": 0,
    "head": {"sha": "<attacker-sha>", "ref": "attacker-ref"},
    "user": {"login": "attacker"}, "assignees": [], "labels": []
  },
  "sender": {"login": "attacker"}
}
```
3. `verify_signature` picks `Shipit.github(organization: "empty-org")`; `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is nil for `empty-org`.
4. `Shipit::Webhooks.for_event('pull_request')` dispatches to `OpenedHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues real review-stack provisioning for `victim-org/victim-repo`, entirely unauthenticated.

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

**File:** config/secrets.development.shopify.yml (L5-18)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

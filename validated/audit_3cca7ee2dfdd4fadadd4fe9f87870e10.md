Confirmed root cause: `Shipit::WebhooksController#verify_signature` in `app/controllers/shipit/webhooks_controller.rb` selects which GitHub-app secret to verify the HMAC signature against using `repository_owner`, which is `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')` — a field taken from the same untrusted, attacker-supplied JSON body it is about to validate. [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the per-organization app config purely by that string, with no cross-check against the repository that the event actually targets: [3](#0-2) 

Once the HMAC passes, every handler determines the target `Stack`/`Repository` from a *different* JSON field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) 

Because the whole raw body is HMAC-signed, an attacker cannot tamper with a payload signed by someone else — but on a multi-tenant Shipit instance (the "Using Multiple Github Applications" configuration, documented in `docs/setup.md` and `lib/shipit.rb`'s `TOP_LEVEL_GH_KEYS`/`github_app_config`), any org that itself has a legitimate GitHub App installed on this Shipit instance knows its own `webhook_secret`. Nothing stops that org's own webhook (or a forged payload signed with that org's own known secret) from carrying `repository.owner.login = "attacker-org"` (used only to pick the verifying key) while `repository.full_name = "victim-org/victim-repo"` (used to resolve the actual `Stack`). `verify_signature` only checks that *some* configured org's secret matches the body; it never asserts that the org whose secret verified the signature is the same org referenced by `repository.full_name` that the handler subsequently acts on. This is exactly the "organization that authenticated versus the repository that is written" binding break called out by the task rules, and it mirrors the report's root cause: a signal produced by the request (or in the report's case, an external call's return status) is not actually verified/bound to the field the code trusts and acts on. [7](#0-6) 

### Title
Webhook signature verification key is selected from an unverified payload field disjoint from the field used to resolve the target repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
On multi-organization Shipit deployments, `WebhooksController#verify_signature` picks the HMAC secret to check by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, then hands the entire parsed body to event handlers, which resolve the actual `Stack`/`Repository` from a different field, `repository.full_name`. The verified "authenticating organization" and the "repository ultimately written to" are never asserted equal.

### Finding Description
`verify_signature` does: `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`, then `Shipit.github(organization: repository_owner)` to fetch the `GitHubApp` (and its `webhook_secret`) used for `verify_webhook_signature`. [1](#0-0) [2](#0-1) 

If the computed HMAC matches, `create` dispatches the full parsed `params` to every registered handler for the event type: [8](#0-7) 

Handlers, however, locate the affected repository/stack via `payload.dig('repository', 'full_name')`, an entirely independent field from the one used for key selection: [4](#0-3) [5](#0-4) 

Nothing in the request pipeline confirms that `repository.full_name`'s owner equals `repository.owner.login`/`organization.login` used to select and verify the signing secret. Any org (`X`) that itself has a legitimate GitHub App configured on the same Shipit instance (a normal supported setup per `docs/setup.md`'s "Using Multiple Github Applications" and `lib/shipit.rb#github_app_config`) knows its own `webhook_secret` value from its own installation, and can therefore produce a validly-signed body where the "authenticating" field says org `X` while the "acted upon" field names a repository under a different org `Y`. [3](#0-2) 

### Impact Explanation
This breaks the binding "organization whose secret authenticated the request == organization whose repository the event mutates." An attacker controlling org `X`'s app config/secret can submit crafted events (e.g. `push`, `pull_request`, `status`, `check_suite`) that pass signature verification under org `X` but drive handlers to enqueue `GithubSyncJob`, create/merge/close `ReviewStack`s, or update commit statuses for an unrelated org `Y`'s repository, if that repository name is guessed/known and has a `Repository`/`Stack` registered on the shared instance. This corresponds to unauthorized cross-repository writes and unauthorized deploy/rollback triggers on a repository the attacker does not control.

### Likelihood Explanation
This requires a Shipit deployment using the multi-organization GitHub App configuration (explicitly documented and supported) where the attacker's own organization is one of the configured apps — i.e., the attacker is a legitimate but unprivileged tenant relative to other tenants on the same instance, not someone needing stolen secrets, GitHub write access, or a Shipit session/API token. This satisfies the "unprivileged attacker" and "no privileged credential required" scope constraints.

### Recommendation
After verifying the signature, re-derive the organization strictly from `repository.full_name`'s owner segment (or `Repository.from_github_repo_name`) and assert it matches the organization whose secret validated the signature (`repository_owner`) before dispatching to handlers; reject the request otherwise.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, `orgX` and `orgY`, each with its own app/`webhook_secret` (per `docs/setup.md`).
2. As an actor with control of org `X`'s GitHub App (attacker's own org), compute a valid `X-Hub-Signature` over a crafted JSON body: `{"repository": {"owner": {"login": "orgX"}, "full_name": "orgY/victim-repo"}, ...push event fields...}` using org `X`'s known `webhook_secret`.
3. POST to `/github/webhooks` with `X-Github-Event: push` and the computed signature.
4. `verify_signature` resolves `repository_owner = "orgX"`, verifies successfully against org `X`'s secret, and allows the request through.
5. `Handler#stacks` resolves `Repository.from_github_repo_name("orgY/victim-repo")`, and the push handler enqueues a `GithubSyncJob`/status update against org `Y`'s stack, despite the request never being authenticated by org `Y`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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

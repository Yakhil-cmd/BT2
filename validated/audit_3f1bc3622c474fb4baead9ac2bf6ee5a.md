## Finding

I found a concrete instance of the report's bug class in this codebase: **the field used to authorize the webhook signature (`repository_owner`) is not the same field used to determine which repository/stack the event actually acts on (`repository.full_name`)**.

### Root cause

`Shipit::WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` is used to validate the incoming `X-Hub-Signature` based on: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')` only when `repository` is absent.

However, the actual event processing — e.g. `Handlers::Handler#stacks` used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc. — resolves the target `Repository`/`Stack` from a **different** field: `payload.dig('repository', 'full_name')`: [3](#0-2) 

Both `repository.owner.login` and `repository.full_name` are attacker-controlled JSON fields in the raw POST body and **neither is itself covered by the HMAC in a way that binds them together** — the signature only proves the request body was signed by *some* configured organization's `webhook_secret`, not that `repository.owner.login` matches `repository.full_name`'s owner segment. In a single-organization deployment (the default `secrets.github` schema, not the `TOP_LEVEL_GH_KEYS` multi-org schema) this is not exploitable because there is only one `webhook_secret` for everything. But in the documented **multi-organization configuration** (`lib/shipit.rb`'s `github_app_config`/`github_organizations`, and `docs/setup.md`'s "Using Multiple Github Applications" section), each organization has its own independent `webhook_secret`: [4](#0-3) [5](#0-4) 

In that configuration, an attacker who is a legitimate collaborator on **their own repository inside Organization A** (and thus knows/can trigger delivery of a validly-signed webhook using Org A's `webhook_secret`, without any Shipit session, API token, or GitHub App key) can craft a raw POST body where `repository.owner.login == "OrgA"` (to select and pass Org A's signature check) while `repository.full_name == "OrgB/victim-repo"` (to route processing to a stack tracked under Org B). Because `Handler#stacks` keys strictly off `repository.full_name`, this event would be dispatched against the victim stack in Org B despite never being verified with Org B's secret.

### Binding broken

`organization authenticated (repository.owner.login, verified against Org A's webhook_secret)` ≠ `repository written (repository.full_name, used to resolve the Stack whose data is mutated)`.

### Impact

For handlers that mutate state based on trusted webhook data (e.g. `StatusHandler` creating commit statuses from arbitrary CI state/description/target_url, `PushHandler` triggering `stack.sync_github` on a victim stack, `CheckSuiteHandler`/`MembershipHandler` mutating team/membership data), an attacker controlling only Org A's webhook secret can inject fabricated events for a **stack belonging to a different, cross-organization repository** they have no legitimate access to — e.g., manufacturing false CI/check-suite state for a competitor's stack, which can influence whether that stack's commits are considered `deployable?`/mergeable, or forcing spurious `GithubSyncJob`/`RefreshCheckRunsJob` on a victim stack.

### Caveats / what I could not fully confirm

- I could not find in-scope code that additionally cross-checks `repository.owner.login` against `repository.full_name`'s owner segment anywhere in the request pipeline (`WebhooksController`, `Handler`, or individual handlers) — the search results show none.
- This is only reachable when the deployment uses the **multi-organization** `secrets.github` schema (multiple orgs, each with distinct `webhook_secret`s) *and* has stacks/repositories tracked across more than one of those organizations. In the common single-org deployment this collapses to a no-op (same secret either way), so exploitability is configuration-dependent, not universal.
- I did not have access to run the actual request pipeline/tests to confirm end-to-end dispatch behavior (e.g., whether `ExplicitParameters::Parameters` or another intermediate step re-validates `repository.owner` against `repository.full_name`); this is inferred from static reading of `webhooks_controller.rb` and `handler.rb`.

### Recommendation

In `WebhooksController#verify_signature`, and/or in `Handlers::Handler#stacks`, enforce that the organization segment of `repository.full_name` matches `repository.owner.login` (or better, resolve the target repository/organization using the *same* field that was used to select the verifying `webhook_secret`) before dispatching to any handler.

### Proof of Concept (conceptual)

1. Deploy Shipit with the multi-org `secrets.github` schema, with `OrgA` and `OrgB` both configured, each with its own `webhook_secret`, and a tracked `Stack`/`Repository` for `OrgB/victim-repo`.
2. As an attacker with a GitHub App/webhook installed on `OrgA` (their own org, no Shipit credentials needed), send:
   ```
   POST /webhooks
   X-Github-Event: status
   X-Hub-Signature: sha1=<HMAC over body using OrgA's webhook_secret>
   Body: {
     "repository": { "owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo" },
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/attacker-forged"
   }
   ```
3. `verify_signature` computes `repository_owner == "OrgA"`, verifies against `OrgA`'s secret — succeeds.
4. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` (global, not scoped to org) and creates a forged status, independent of which org's secret validated the request. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

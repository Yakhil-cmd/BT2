This confirms the mechanism precisely: `Shipit.github(organization: repository_owner)` selects a per-organization `GitHubApp` instance based solely on `repository_owner`, which is parsed straight from the untrusted webhook body via `params.dig('repository', 'owner', 'login')` [1](#0-0) . That instance's `webhook_secret` is then used to verify the HMAC signature, but if the org's `webhook_secret` is unset, verification is unconditionally bypassed [2](#0-1) . Meanwhile, every event handler determines which `Repository`/`Stack` to act on using a *different* field from the same payload — `payload.dig('repository', 'full_name')` — with no cross-check against `owner.login` [3](#0-2) , and this is used identically across `PushHandler`, `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, and `LabelCapturingHandler` [4](#0-3) [5](#0-4) .

### Title
Cross-organization webhook forgery via decoupled signature-selection and repository-write fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The Shipit engine supports hosting multiple GitHub organizations from a single instance, each with its own independently configured `webhook_secret` [6](#0-5) . The webhook controller selects which organization's secret to verify a request against using `repository.owner.login` from the untrusted JSON body itself [7](#0-6) . All downstream handlers, however, resolve the actual `Repository`/`Stack` to mutate using a separate field, `repository.full_name` [3](#0-2) . Because these two fields are never cross-validated against each other, and because `verify_webhook_signature` unconditionally returns `true` whenever the resolved organization has no `webhook_secret` configured (a documented, supported configuration state — see `webhook_secret: # nil` in `config/secrets.development.example.yml`) [2](#0-1) [8](#0-7) , an unauthenticated attacker can forge a webhook body claiming `owner.login` for an organization with no secret configured while setting `full_name` to point at a stack that belongs to a completely different, secret-protected organization.

### Finding Description
`WebhooksController#verify_signature` computes the organization used for signature verification purely from attacker-supplied JSON: `params.dig('repository', 'owner', 'login')` [1](#0-0) . This drives `Shipit.github(organization: repository_owner)`, which looks up per-org config via `github_app_config` [9](#0-8) , and the resulting `GitHubApp#verify_webhook_signature` trivially returns `true` if that org's `webhook_secret` is blank [2](#0-1) .

Once the request passes this check, `WebhooksController#create` dispatches the *entire, unmodified* raw payload to every registered handler for the event type [10](#0-9) . These handlers never re-derive or re-check `owner.login`; instead they resolve the target `Repository` via `payload.dig('repository', 'full_name')` [11](#0-10) , which is an independent string in the same JSON body that GitHub normally keeps consistent with `owner.login`, but which nothing in Shipit enforces to be consistent when the request is attacker-crafted.

Equality that should hold but doesn't:
`organization_whose_secret_authenticated_the_request == organization_that_owns_the_repository_being_written_to`

Before the attack: only whichever org's webhook signature is verified can affect that org's own stacks. After the attack: an attacker who merely knows (or exploits the absence of) one org's `webhook_secret` can supply `owner.login` = that org, `full_name` = `"other-protected-org/some-repo"`, and have the signature check pass while the write happens against `other-protected-org`'s stack (e.g. triggering `GithubSyncJob`, archiving/unarchiving review stacks, capturing PR labels, closing review stacks, creating commit statuses, etc.), entirely bypassing that org's own webhook secret.

### Impact Explanation
This breaks the "organization authenticated versus repository written" binding explicitly called out as in-scope. Concretely, an attacker can trigger unauthorized write-side effects against a stack belonging to an organization they have no relationship to: forcing `GithubSyncJob` runs (`PushHandler`), archiving/unarchiving review stacks and altering provisioning behavior (`LabeledHandler`/`UnlabeledHandler`/`ClosedHandler`/`ReopenedHandler`), capturing/spoofing PR labels used for deploy gating (`LabelCapturingHandler`), or injecting fabricated commit statuses/check-run data that influence `Commit#deployable?` and thus what continuous deployment is willing to ship. This can be leveraged to unlock or trigger an unauthorized deploy path on a stack whose organization the attacker does not control, matching the High-severity "escalation into authorization" / cross-repository-write class in scope.

### Likelihood Explanation
Likelihood is high in any multi-organization Shipit deployment where at least one configured organization leaves `webhook_secret` unset — an explicitly documented and supported configuration (`webhook_secret: # nil`). No credentials, session, or prior access are required; the attacker only needs to POST a crafted JSON body to the public `/webhooks` endpoint with a mismatched `owner.login` / `full_name` pair and the correct `X-Github-Event` header.

### Recommendation
Cross-validate that `repository.full_name`'s owner segment matches `repository.owner.login` (and reject mismatches) before dispatching to handlers, or better, derive the authorizing organization strictly from `repository.full_name` so the same field used for signature-org selection is the one used for the write target. Additionally, warn/refuse to boot in a multi-org configuration where any configured organization has a blank `webhook_secret`, since that organization becomes a bypass vector for every other organization hosted on the same Shipit instance.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `OrgOpen` (no `webhook_secret`) and `OrgProtected` (has a real `webhook_secret`, hosts a stack `OrgProtected/prod-app`) as shown in `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgOpen" }, "full_name": "OrgProtected/prod-app" }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgOpen"`, calls `Shipit.github(organization: "OrgOpen")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. `PushHandler#process` runs `Repository.from_github_repo_name("OrgProtected/prod-app")` and enqueues `GithubSyncJob` for that stack, an org the attacker never authenticated against.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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

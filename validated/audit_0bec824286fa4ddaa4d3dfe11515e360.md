### Title
Webhook signature verification keyed on attacker-controlled `repository.owner.login` while handlers act on a different payload field `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC signature against using an organization name pulled straight out of the unauthenticated JSON payload, while the webhook handlers that actually write data (enqueue syncs, create commits/statuses, mutate stacks) key off a completely different field of the same payload. In a multi-organization deployment where at least one configured organization has no `webhook_secret` set, this breaks the intended binding "organization whose signature was verified" == "repository that gets written to."

### Finding Description
`verify_signature` computes the verification organization purely from request JSON, not from anything cryptographically bound to the sender: [1](#0-0) 

That value is then used to select which `GitHubApp` (and thus which `webhook_secret`) to verify the signature with: [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected app's `webhook_secret` is blank: [3](#0-2) 

Meanwhile, `Shipit.github_app_config` / `Shipit.github` resolve per-organization config from `secrets.github`, and the docs/test fixtures explicitly show that per-organization `webhook_secret` is optional and can be `nil` for a given org in a multi-org config: [4](#0-3) 

Once past `verify_signature`, the actual handlers ignore `repository.owner.login` entirely and instead resolve the target repository/stack from `repository.full_name`: [5](#0-4) 

So the field used to pick the verifying secret (`repository.owner.login`) and the field used to pick the repository that gets written to (`repository.full_name`) are two independent, attacker-supplied JSON keys in the same unauthenticated payload. An attacker who knows (or guesses) that one configured organization in `secrets.github` has no `webhook_secret` set can send a payload with `repository.owner.login` set to that unsecured org, causing `verify_webhook_signature` to return `true` unconditionally, while setting `repository.full_name` to point at a stack that belongs to a *different*, secured organization. The handler dispatch (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) then processes the forged event against that other stack — enqueuing `GithubSyncJob`, creating commit statuses, closing/labeling pull requests, etc. — without ever having verified a signature tied to the actually-affected repository's owner.

### Impact Explanation
This breaks the binding "the organization whose webhook secret authenticated the request" == "the repository/stack that is written." In a Shipit instance configured for multiple GitHub organizations (a documented, supported configuration per `github_organizations`/`TOP_LEVEL_GH_KEYS`), an unprivileged external attacker can forge webhook events (push, status, check_suite, pull_request, membership) against any stack belonging to a *properly secured* organization, as long as any other configured organization in the same instance has no `webhook_secret`. This can trigger unauthorized `GithubSyncJob` runs, fabricate commit statuses that gate deploys, or manipulate merge-queue pull-request handlers — i.e., cross-repository/cross-organization writes and potentially unauthorized deploy triggering, matching the "cross-repository writes" / "unauthorized deploy" impact tier.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment, and (2) at least one configured organization with no `webhook_secret`. This is a supported and documented configuration (webhook secret is described as optional in `docs/setup.md`), so it is plausible in real deployments, though it depends on operator configuration rather than being universally exploitable. No credentials, session, or repository access are required by the attacker — only knowledge of one organization's login name and network reachability to `/webhooks`.

### Recommendation
Do not select the verifying `GitHubApp`/secret based on unauthenticated payload data. Either verify the signature against every configured organization's secret (or against the specific secret bound to the organization actually referenced by `repository.full_name`), and reject if none of them validate. Additionally, refuse to treat `verify_webhook_signature` as "pass" when `webhook_secret` is blank for multi-tenant configs — require an explicit opt-in for "no secret" per organization, and cross-check that the verified organization matches the owner of `repository.full_name` before dispatching handlers.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `OrgA` (has `webhook_secret: s3cr3t`, hosts a sensitive stack `OrgA/prod-repo`) and `OrgB` (no `webhook_secret`, e.g. a low-trust sandbox org also installed on the instance).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and JSON body:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/prod-repo" },
  "after": "<attacker-chosen-sha>"
}
```
3. `repository_owner` resolves to `OrgB`; `Shipit.github(organization: "OrgB")` returns a `GitHubApp` with blank `webhook_secret`; `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/invalid) signature header.
4. The push handler in `Shipit::Webhooks.for_event('push')` resolves the target stack via `repository.full_name` = `OrgA/prod-repo`, enqueuing `GithubSyncJob` for `OrgA`'s stack — a write triggered by a request that never validated against `OrgA`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

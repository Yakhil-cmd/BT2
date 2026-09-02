### Title
Cross-organization webhook forgery via `repository_owner`/`repository.full_name` binding mismatch in multi-org GitHub App config - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App config (and therefore which `webhook_secret`) to validate a webhook against using `repository_owner`, a value pulled straight out of the still-unauthenticated JSON body. The rest of the pipeline (`Shipit::Webhooks::Handlers::Handler#stacks`) resolves the actual `Stack`/`Repository` to act on using a *different* field of the same unauthenticated body: `repository.full_name`. Nothing enforces that these two fields agree, so in a multi-organization deployment the field that gates authentication (`repository.owner.login` / `organization.login`) and the field that determines which repository's data gets written (`repository.full_name`) can point at two different organizations.

### Finding Description
`verify_signature` computes the org used for verification like this: [1](#0-0) [2](#0-1) 

That org name is used to fetch a `GitHubApp` instance via `Shipit.github(organization: repository_owner)`, which looks up per-organization config, including `webhook_secret`: [3](#0-2) 

Signature verification for that app instance is: [4](#0-3) 

Note `return true unless webhook_secret` — if the organization resolved from the attacker-controlled `repository_owner`/`organization.login` field has **no `webhook_secret` configured** (a supported, documented configuration — see `config/secrets.development.example.yml` and multi-org examples where `webhook_secret:` is left blank per-org), verification trivially passes for *any* payload, regardless of the `X-Hub-Signature` header.

Meanwhile, the event handlers never re-check that organization; they resolve the target repository purely from `repository.full_name`: [5](#0-4) 

Both `repository.owner.login` and `repository.full_name` are read from the same unauthenticated JSON body (`request.raw_post`) before/independent of any binding between them. There is no requirement that `full_name`'s owner segment match `owner.login`. Thus the binding that is actually enforced is:

`organization used for signature-secret lookup (repository_owner)` ≠ `organization implied by the repository actually written to (repository.full_name)`

**Before the attack:** a legitimately configured, secret-less org (e.g., a low-value/staging org configured under `github:` in `secrets.yml` per the multi-org schema) is deliberately treated by the operator as "no real webhooks expected/low risk". **After the attack:** an unauthenticated party crafts a webhook body claiming `repository.owner.login`/`organization.login = <secret-less-org>` while setting `repository.full_name = <victim-org>/<victim-repo>` (a repo that *does* have a tracked, secret-protected `Stack`). `verify_signature` looks up the secret-less org, finds no secret, and returns `verified = true` unconditionally, so `head(422)` is never triggered even though `head(422)` executes it doesn't halt — actually more importantly, the request is processed and dispatched to handlers, which act on `repository.full_name` (the victim repo).

### Impact Explanation
This lets an unauthenticated attacker inject arbitrary, fully-controlled webhook events (`push`, `status`, `check_suite`, `pull_request`, `merge`, `deployment_status`, `membership`, etc.) against any tracked victim `Stack`/`Repository`, as long as the deployment has at least one configured organization without a `webhook_secret`. Concretely this can be used to:
- Forge `push` events to enqueue `Shipit::GithubSyncJob` for a victim stack with attacker-influenced `expected_head_sha`, or forge `status`/`check_suite` events to inject fabricated commit statuses/check runs, which downstream deploy-gating logic (deployable status checks) trusts as coming from GitHub.
- Forge `membership` events to create/delete `Team`/`Membership`/`User` records, directly manipulating `Shipit.github_teams`-derived authorization data.

This is an authentication bypass of the webhook trust boundary (GitHub's HMAC signature) and an escalation path into stack/commit-status state and `Shipit.github_teams`-linked membership data for a repository the attacker does not control, satisfying the "escalation into `Shipit.github_teams` authorization" / "unauthenticated read... task streams" class of High severity impact (and, if a deploy is subsequently allowed because of forged status checks, edges into the unauthorized-deploy Critical category).

### Likelihood Explanation
Requires no credentials, tokens, or GitHub App private keys — only that the target instance is configured with the documented multi-organization schema and that at least one configured organization omits `webhook_secret` (explicitly shown as an allowed value — `webhook_secret: # nil` — in the shipped example configs). This is a plausible, realistic operational configuration (e.g., an internal/staging org added without bothering to set a webhook secret), making likelihood moderate; it depends on the host's configuration choice rather than a universal default.

### Recommendation
- Do not let the field used to pick the verification secret (`repository_owner`/`organization.login`) diverge from the field used to resolve the acted-upon repository (`repository.full_name`). Verify that the owner segment of `repository.full_name` matches the resolved `repository_owner` before dispatching to handlers.
- Do not treat a missing `webhook_secret` as "skip verification" (`return true unless webhook_secret` in `lib/shipit/github_app.rb`); require every configured organization to have a webhook secret, or fail closed instead of open when one is absent.
- After signature verification with organization X's secret, ensure downstream handlers only ever touch repositories provably owned by X (not merely `repository.full_name` taken from the raw body).

### Proof of Concept
1. Deploy Shipit with multi-org config: `OrgA` (victim, has `webhook_secret` set, hosts tracked `Stack` "OrgA/victim-repo") and `OrgB` (has no `webhook_secret` configured).
2. Send an unauthenticated `POST /github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/victim-repo" },
  "after": "<attacker chosen sha>"
}
```
No `X-Hub-Signature` header (or an arbitrary bogus one) is needed.
3. `WebhooksController#verify_signature` computes `repository_owner = "OrgB"`, fetches `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally. [6](#0-5) 
4. The request proceeds to `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }`, and the push handler resolves the target stack via `Repository.from_github_repo_name("OrgA/victim-repo")`, enqueueing `GithubSyncJob` against the victim's `Stack` — despite the request never having a valid signature for `OrgA`. [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

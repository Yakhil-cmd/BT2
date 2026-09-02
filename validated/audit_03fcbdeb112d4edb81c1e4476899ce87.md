### Title
Forged webhook events can hijack a repository whose configured GitHub organization uses no `webhook_secret`, enabling unauthorized deploys and team-membership escalation - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App config (and thus which `webhook_secret`) to validate a webhook against using an **attacker-controlled** field from the unauthenticated request body (`repository.owner.login` / `organization.login`), before the signature has been checked. If the organization resolved from that field has no `webhook_secret` configured — which the setup docs explicitly describe as **optional** — `verify_webhook_signature` short-circuits and accepts the request unconditionally. The event handlers then act on `repository.full_name` taken from that same forged payload, so an attacker can point the "authenticated" organization at an org with no secret while the "acted upon" repository is any tracked stack, mirroring the report's fee-griefing pattern: a value that is checked (`highWaterMark`/signature-organization) is decoupled from the value that is actually mutated (`fees.feesUpdatedAt` / the target repository).

### Finding Description
`repository_owner` is derived purely from the untrusted JSON body: [1](#0-0) [2](#0-1) 

This value is used to select the `GitHubApp` instance/config used only to verify the signature: [3](#0-2) 

And `verify_webhook_signature` treats a missing secret as automatic success: [4](#0-3) 

Meanwhile every event handler resolves the actual target `Stack`/`Repository` from `payload.dig('repository', 'full_name')` — the same forged payload, but not the field used for signature-org selection: [5](#0-4) 

The binding that should hold is:
`organization used to verify HMAC(signature) == organization owning the repository the handler mutates`

An attacker breaks this by submitting `repository.owner.login` (or `organization.login`) equal to some org **A** configured in this Shipit instance with `webhook_secret: nil` (documented as optional, e.g. in `docs/setup.md` and the sample `config/secrets*.yml` files), while setting `repository.full_name` to `victimOrg/victim-repo` for a *different*, secret-protected org **B** that Shipit is also tracking. Verification passes trivially for org A, but the handler dispatch operates on org B's repository.

### Impact Explanation
Because signature verification is bypassed for any tracked repository as long as one configured org has no secret, an attacker can forge arbitrary GitHub webhook events for a repository they do not control:
- A forged `status` event can flip an existing commit's CI state to `success`, satisfying `deployable?`/`branch_status` checks and, combined with `continuous_deployment`, trigger `ContinuousDeliveryJob` to deploy that commit without CI ever having passed — an **unauthorized deploy**, per `Shipit::Commit` continuous-delivery scheduling logic.
- A forged `membership` event is handled by `membership_handler.rb`, creating/joining `Team`/`User` records that feed `Shipit.github_teams`, which governs OAuth authorization: [6](#0-5) 
This is an escalation into `Shipit.github_teams` authorization.

Both outcomes map directly to the report's in-scope Critical/High impact categories (unauthorized deploy; escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
Requires a Shipit deployment configured with multiple GitHub organizations (explicitly documented and supported, see `docs/setup.md` "Using Multiple Github Applications") where at least one organization omits `webhook_secret` (also explicitly documented as optional). No prior authentication, API token, or repository access is needed — only knowledge of another tracked org's name that has no secret configured, discoverable via public GitHub org membership/documentation of the target Shipit deployment.

### Recommendation
- Verify the webhook signature using a webhook_secret bound to the actual target repository (`repository.full_name`) being acted upon, not a caller-suppliable `owner.login`/`organization.login` field, or require the resolved organization to match the owner segment of `repository.full_name`.
- Treat a missing `webhook_secret` as "reject all webhooks for this org" rather than "accept all", or require `webhook_secret` to be mandatory for any multi-org configuration.
- Add a check in `Handlers::Handler` that the organization used for signature verification equals the owner of `repository_name` before dispatching.

### Proof of Concept
1. Operator configures Shipit with two GitHub Apps: `victimOrg` (with `webhook_secret` set, tracking a sensitive stack) and `noSecretOrg` (with `webhook_secret` left blank, per the documented-optional setting).
2. Attacker (no credentials) sends `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "organization": { "login": "noSecretOrg" },
  "repository": { "owner": { "login": "noSecretOrg" }, "full_name": "victimOrg/victim-repo" },
  "sha": "<existing pending/failing commit sha in victim-repo>",
  "state": "success",
  "branches": [{ "name": "main" }]
}
```
with any/garbage `X-Hub-Signature`.
3. `verify_signature` resolves `repository_owner` → `"noSecretOrg"`, calls `Shipit.github(organization: "noSecretOrg").verify_webhook_signature(...)`, which returns `true` unconditionally because `webhook_secret` is blank for that org.
4. `create` dispatches the `status` handler using `payload.dig('repository','full_name') == "victimOrg/victim-repo"`, creating a `success` status on the targeted commit in `victimOrg`'s stack.
5. If `victimOrg`'s stack has `continuous_deployment: true`, this forged status can make the commit deployable and trigger an unauthorized deploy.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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

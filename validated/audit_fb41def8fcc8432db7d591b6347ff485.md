### Title
Cross-Organization Webhook Confused Deputy via Unverified `repository.owner.login` / `repository.full_name` Binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an inbound webhook against by reading an **unauthenticated field of the request body itself** (`repository.owner.login`, falling back to `organization.login`), while every `Webhooks::Handlers::Handler` subsequently resolves the actual `Repository`/`Stack` to mutate using a **different, independently-controlled field of the same body** (`repository.full_name`). Nothing ties these two fields together, so the organization whose secret authenticated the request is never checked against the repository that ends up being written to.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it purely to pick which `GitHubApp` (and thus which `webhook_secret`) to verify against: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```

`GitHubApp#verify_webhook_signature` explicitly treats a **blank `webhook_secret` as "always verified"**: [3](#0-2) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```

Shipit supports multiple independently-configured GitHub organizations/Apps in a single deployment (`Shipit.github(organization:)`, `Shipit.github_app_config`), each with its own `webhook_secret`, as shown by the multi-org fixture used in the test suite where **both** orgs have `webhook_secret: # nil`: [4](#0-3) [5](#0-4) 

Meanwhile, every handler resolves the target repository/stack purely from `repository.full_name`, completely independent of the organization used for signature verification: [6](#0-5) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` then acts on all matching stacks: [7](#0-6) 

**Binding broken (equality that should hold but doesn't):**
`organization_that_authenticated(request) == organization_that_owns(repository_written)`

Before the attacker acts: for a legitimately-delivered GitHub webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always the same real repository, so the equality trivially holds and signature verification against `repository.owner.login`'s secret is meaningful.

After the attacker acts: an unprivileged actor crafts a raw POST body where `repository.owner.login` is set to any organization configured in Shipit **without** a `webhook_secret` (a supported, real configuration state per the fixture above), while `repository.full_name` is set to `"<protected-org>/<protected-repo>"` — a stack belonging to an organization that *does* have a secret configured. `verify_signature` looks up the GitHub App for the unprotected org, whose `verify_webhook_signature` unconditionally returns `true` regardless of the `X-Hub-Signature` header content, so the request passes. The handler then acts on the protected org's real stack because it only ever reads `repository.full_name`.

### Impact Explanation
This is an authentication-bypass / confused-deputy issue: signature verification is bound to one payload field while the state-mutating action is bound to a different, unrelated field, and an attacker fully controls both fields in an unsigned HTTP request. Concretely reachable handlers that mutate protected state without any authenticated relationship to the attacker-chosen `full_name` include: `PushHandler` (`stack.sync_github`), `Handlers::StatusHandler` (creates commit `Status` from `state`/`description`/`target_url`, which can feed CI-gated continuous delivery decisions), and `Handlers::MembershipHandler` (creates/deletes `Team`/`Membership`/`User` records used by `Shipit.github_teams` authorization checks — see `User#authorized?`). Fabricated commit statuses or membership changes can influence whether a deploy/merge is permitted for the real, protected stack, satisfying the "unauthorized deploy" / "escalation into `Shipit.github_teams` authorization" impact classes even though the attacker never possessed the protected organization's `webhook_secret`.

### Likelihood Explanation
This requires the deployment to actually run more than one GitHub organization/App configuration where at least one configured organization has no `webhook_secret` set — a state the codebase explicitly supports and even ships as a test fixture (`secrets_double_github_app.yml`), rather than a hypothetical misconfiguration invented for this report. Any operator running a multi-tenant Shipit instance where a lower-trust org is configured (e.g., during onboarding, before a secret is rotated in, or deliberately left blank because that org is believed "not sensitive") exposes every other org's repositories to this cross-org write, because the exploited endpoint (`Shipit::WebhooksController#create`) requires no session, API token, or GitHub credential — only knowledge of any repository's `full_name` in the fleet, which is not secret.

### Recommendation
Do not use an attacker-controlled field of the unauthenticated payload to select the verification key and then use a different field for the actual mutation. Concretely:
1. In `WebhooksController#verify_signature`, treat a blank `webhook_secret` for an organization as a hard misconfiguration to be rejected (or require an explicit "insecure" opt-in), rather than silently returning `true`.
2. After signature verification succeeds, re-derive `repository_owner` and assert it matches the owner segment of `repository.full_name` (or, better, resolve the target `Repository`/`Stack` and check its owning organization equals the org whose key verified the request) before dispatching to any handler; reject the request otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgLow` (no `webhook_secret`) and `OrgHigh` (real secret, owns stack `OrgHigh/critical-repo`) — mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. As an unauthenticated attacker, POST to `/webhooks` (or the engine-mounted webhook path) with header `X-Github-Event: push` and no valid `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-on-github>",
  "repository": {
    "owner": { "login": "OrgLow" },
    "full_name": "OrgHigh/critical-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgLow")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking the header at all.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgHigh/critical-repo")` and invokes `stack.sync_github(expected_head_sha: ...)` on the real, protected stack — a state-changing action triggered by a request that was never signed by `OrgHigh`'s webhook secret.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

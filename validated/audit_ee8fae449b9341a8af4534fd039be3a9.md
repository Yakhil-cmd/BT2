Confirmed. The vulnerability is fully reachable and exactly matches the required binding pattern: "organization that authenticated versus the repository that is written." [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Webhook signature is verified against the organization named in `repository.owner.login`, while handlers write to the repository named in `repository.full_name` — allows cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the **unauthenticated** JSON body itself, but every `Shipit::Webhooks::Handlers::Handler` subclass resolves the repository/stack to mutate using a **different** field, `repository.full_name`, from the same attacker-supplied body. In a multi-organization Shipit deployment, an attacker who can produce a validly-signed (or unsigned, if `webhook_secret` is unset) payload for *any one* configured organization can set `repository.full_name` to point at a repository belonging to a *different* configured organization, and the handlers will act on it — completely bypassing that other organization's webhook secret.

### Finding Description
`verify_signature` computes the GitHub App instance to check the signature against like this:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`repository_owner` is read straight from the untrusted, not-yet-verified JSON body, and used to pick a configured organization's `GitHub App` (and thus its `webhook_secret`) via `Shipit.github(organization:)` / `Shipit::GitHubApp#verify_webhook_signature`.

Meanwhile, every webhook handler (`PushHandler`, `PullRequest::OpenedHandler`, `StatusHandler`, etc.) resolves the target repository independently, from a *different* key in the same payload:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
```
`Handler#stacks` and `ReviewStackAdapter#repository` use this `full_name` to look up `Repository.from_github_repo_name`, i.e. to find/create the `Stack`, sync commits, create/archive `ReviewStack`s, create `Shipit::User`/`Team` records, and post commit `Status`.

Nothing in the code ties `repository.owner.login` to `repository.full_name`; they are simply two independent fields of the same attacker-controlled JSON document. In a Shipit instance configured with `Shipit.github_organizations` containing multiple organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`), an attacker who can obtain a valid signature for **any one** configured organization (e.g. a low-value org whose `webhook_secret` is weak, guessable, or intentionally left `nil` as shown in the sample configs) can:
1. Set `repository.owner.login` = that organization (so `verify_signature` selects that org's `GitHub App`/secret and the signature check passes, or trivially passes because `verify_webhook_signature` returns `true` whenever `webhook_secret` is blank).
2. Set `repository.full_name` = `"victim-org/victim-repo"`, targeting a repository actually tracked by Shipit under a *different*, properly-secured organization.
3. The handlers act exclusively on `repository.full_name`, so the forged event is applied to the victim stack as if it came from GitHub itself.

This breaks the equality that should hold: `organization whose signature verified == organization owning the repository being written`.

### Impact Explanation
This crosses a genuine cross-organization/cross-repository write and authentication-bypass boundary reachable by an unprivileged network attacker (no Shipit session, API token, or GitHub credentials needed — only knowledge/possession of one organization's webhook secret, which the codebase and docs explicitly allow to be absent/`nil`):
- `status` events can forge a passing CI status for any commit of the victim stack, which feeds into `Commit#deployable?` checks used to gate deploys — an unauthorized-deploy vector.
- `pull_request` events can create/unarchive `ReviewStack`s for the victim repository, which provisions and runs the repository's `shipit.yml` steps on the deploy host — a path toward RCE on the deploy host.
- `push`/`check_suite` events force out-of-band Github sync jobs and check-run refreshes for stacks the attacker does not own.
- `membership` events can create/delete `Team`/`Membership` records that back `Shipit.github_teams` authorization checks used elsewhere (e.g. `ApiClientsController`), enabling escalation into team-gated authorization.

### Likelihood Explanation
Any Shipit instance following the documented multi-organization setup (`docs/setup.md`, sample `config/secrets.*.yml` files all show `webhook_secret: # nil` as a valid template value) is exposed as soon as at least one configured organization has no `webhook_secret` set, or its secret is weaker/known. The `/webhooks` endpoint is unauthenticated by design (that's its purpose), so the only barrier is obtaining a signature valid for *one* org, not the target org.

### Recommendation
Verify the webhook signature using the organization actually implicated in `repository.full_name` (or better, using the organization that owns the `Repository`/`Stack` record found by `full_name`), not a value taken from an unrelated field of the same unverified body. Additionally, enforce that `repository.owner.login` and the owner segment of `repository.full_name` match before any handler processes the payload, and treat `webhook_secret` as mandatory (reject configuration/requests when absent) rather than silently treating a missing secret as "always verified."

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled or with `webhook_secret` unset/weak) and `OrgB` (victim, properly secured), both tracked (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Craft a `pull_request` (or `status`) webhook body:
```json
{
  "action": "opened",
  "number": 999,
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "pull_request": { ... },
  "sender": { "login": "attacker" }
}
```
3. Sign the request with `OrgA`'s `webhook_secret` (or send unsigned if `OrgA.webhook_secret` is `nil`), set `X-Github-Event: pull_request`, POST to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and passes verification using `OrgA`'s (weak/absent) secret.
5. `PullRequest::OpenedHandler` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and creates/updates a `ReviewStack` for the victim organization's repository — a forged write into `OrgB`'s trust domain despite never possessing `OrgB`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

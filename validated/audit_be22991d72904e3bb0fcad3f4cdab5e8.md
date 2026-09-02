### Title
Webhook signature verified against one organization while the acted-upon repository is read from an attacker-controlled field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to check against using `repository_owner`, which is read from the same untrusted JSON body it is about to validate. Downstream handlers then act on a different field of that same body (`repository.full_name`) to decide which `Stack`/`Repository` to mutate. Because Shipit supports multiple organizations each with an independent `webhook_secret` [1](#0-0) , the "organization whose secret authenticated the request" and the "repository that is actually written to" are two independently attacker-controlled fields inside one signed payload, breaking the binding: `organization_verified == organization_of_repository_acted_on`.

### Finding Description
`verify_signature` computes the organization to verify against directly from the incoming JSON body: [2](#0-1) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
```
and [3](#0-2) 
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up per-organization config, including a distinct `webhook_secret`, from `config/secrets.yml`/Rails credentials for each configured GitHub organization [1](#0-0) . This multi-organization layout is a supported, documented configuration (see `test/dummy/config/secrets_double_github_app.yml`, which configures `OrgOne` and `OrgTwo` with independent secrets).

After signature verification passes, event handlers (e.g. `PushHandler`, `StatusHandler`, PR handlers) resolve the target `Repository`/`Stack` using `Handler#repository_name`, which reads a *different* field of the same JSON body: [4](#0-3) 
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Because both `repository.owner.login` (used to pick the verification secret) and `repository.full_name` (used to pick the repository actually mutated) are attacker-supplied fields inside the same payload, an attacker who legitimately controls a GitHub App installed on *any one* of the organizations configured in this Shipit instance (and therefore knows/can obtain that organization's `webhook_secret`, since they administer that GitHub App) can:
1. Sign a payload with their own organization's webhook secret (`repository.owner.login = "attacker-org"`), which is what `verify_signature` checks and accepts.
2. Set `repository.full_name = "victim-org/victim-repo"` in the same payload, which is what the handler uses to resolve the `Stack`/`Repository` to act on.

`verify_signature` never checks that the organization used to select the secret matches the organization embedded in `repository.full_name`; the two lookups are performed independently on the same untrusted JSON, breaking the trust binding `organization_authenticated == repository_written`.

### Impact Explanation
This allows cross-repository writes: an attacker with legitimate control of a GitHub App/webhook secret for one onboarded organization can forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are accepted as authentic and dispatched against a completely different organization's repositories/stacks that they do not control. Depending on the handler this can trigger unwanted `GithubSyncJob` runs, fabricate commit statuses that gate deploys, or manipulate PR/merge-related state for another team's stack — an unauthorized cross-repository action performed without ever having the credentials, session, or `ApiClient` token for the victim's repository. This matches the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Exploitability requires the attacker to be a legitimate administrator of at least one organization already onboarded to the shared Shipit instance (so they know that organization's `webhook_secret`), which is a realistic multi-tenant deployment scenario explicitly supported and tested in this codebase (`test/dummy/config/secrets_double_github_app.yml`). No Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required — only knowledge of one configured organization's webhook secret, obtainable by anyone administering that org's GitHub App settings.

### Recommendation
In `WebhooksController#verify_signature`, after determining the organization used for signature verification, cross-check it against the organization embedded in `repository.full_name` (or `organization.login`) and reject the request if they diverge. Alternatively, derive the repository/stack lookup in `Handler#repository_name` from the same verified `repository_owner` used during signature verification rather than independently re-parsing `repository.full_name`, so a single authenticated field drives both the signature check and the write target.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (a supported configuration, see `test/dummy/config/secrets_double_github_app.yml`).
2. As an administrator of `attacker-org`'s GitHub App, obtain `attacker-org`'s `webhook_secret`.
3. Craft a `push` event payload:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
4. Sign the raw JSON body with `attacker-org`'s `webhook_secret` using HMAC-SHA1 and set it in the `X-Hub-Signature` header; set `X-Github-Event: push`.
5. POST to `/github/webhooks` (the `WebhooksController#create` route). `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's known secret [5](#0-4) .
6. `PushHandler`/`Handler#stacks` resolves the target using `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` [4](#0-3) , causing Shipit to act on `victim-org`'s stack even though the signature was verified against `attacker-org`'s secret.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

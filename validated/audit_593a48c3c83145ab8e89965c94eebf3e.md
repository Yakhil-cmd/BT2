### Title
Cross-organization commit status forgery: webhook signature is scoped to the payload's own org, but `StatusHandler` writes to any commit regardless of which org signed the request - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check against based on an organization name taken from the same payload it is verifying, and Shipit explicitly supports a multi-organization configuration where each organization has its own independent `webhook_secret`. `StatusHandler`, however, applies the resulting `commit_status` update to any `Commit` matching `params.sha` in the entire database, with no check that the SHA belongs to a repository owned by the organization whose secret validated the signature. This breaks the binding "organization authenticated == repository/commit written".

### Finding Description
Verification picks the GitHub App/secret using a field pulled straight out of the untrusted payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` is designed for multi-tenant deployments, where distinct organizations each configure their own `webhook_secret` under `github_app_config`: [3](#0-2) 

The HMAC check only proves that *someone who knows organization X's webhook secret* produced this exact payload - it does not constrain which `repository`/`sha` fields appear inside that payload: [4](#0-3) 

After verification, the controller dispatches to handlers with the raw, attacker-controlled `params`: [5](#0-4) 

The base `Handler` class does scope lookups to the repository named in the payload for handlers that use it (e.g. `PushHandler`): [6](#0-5) 

But `StatusHandler` does not use this repository-scoping helper at all - it looks up commits purely by `sha`, globally, across every stack/repository tracked by the Shipit instance: [7](#0-6) 

Equality that is supposed to hold: `organization_that_signed_the_webhook == owner_of_the_repository_whose_commit_status_is_written`. Because the signing organization is derived from the same untrusted JSON body (`repository.owner.login` / `organization.login`) and the acted-upon field (`sha`, and for other handlers `repository.full_name`) is a completely independent field in that same body, an attacker who legitimately knows *any one* configured organization's `webhook_secret` (e.g., they administer their own org's GitHub App installation in a multi-org Shipit deployment) can set `repository.owner.login` to their own org (so the HMAC check passes with a secret they know) while setting `sha` to a commit SHA that actually belongs to a completely different organization's stack.

### Impact Explanation
Commit statuses gate deploys via the `ci.require` configuration (documented statuses that must be green before continuous delivery deploys a commit). By forging a `status` webhook event signed with an org's own secret but targeting a SHA from a different organization's tracked stack, an attacker can:
- Mark an arbitrary commit belonging to another organization's stack as `success` for any `context`, bypassing real CI gating and enabling an unauthorized deploy of that commit once other conditions are met, or
- Mark a legitimate commit as `failure`/`error`, blocking deploys (denial of a specific deploy path, though DoS in general is out of scope, the ability to falsify CI state to force/permit an unauthorized deploy is the in-scope impact).

This crosses the "organization authenticated vs. repository/commit written" boundary and can lead to an unauthorized deploy, which is explicitly a High-impact category in scope.

### Likelihood Explanation
This requires the Shipit instance to be configured in the multi-organization mode (`github_app_config`/per-org `webhook_secret`, an explicitly supported and documented configuration in `lib/shipit.rb`) and requires the attacker to legitimately control at least one of the configured organizations (i.e., know that org's own `webhook_secret`, which they set themselves when installing the GitHub App on their org). No repository write access, GITHUB_TOKEN, or Shipit session is required - only the webhook secret of an organization the attacker is entitled to administer, which is an unprivileged-attacker-with-respect-to-other-orgs scenario matching the required threat model.

### Recommendation
When multiple organizations are configured, `StatusHandler` (and any other handler that doesn't already scope by `repository_name`) must verify that the commit/stack being acted upon actually belongs to a repository whose owner matches the organization that produced a validated signature, rejecting the event otherwise. More generally, `WebhooksController#verify_signature` should bind the verified organization identity into the request context and every handler should re-check that any repository/commit/stack it mutates belongs to that same, already-verified organization before writing.

### Proof of Concept
1. Deploy Shipit with the multi-org config (`config/secrets.yml` containing `github: { org_a: {webhook_secret: SECRET_A, ...}, org_b: {webhook_secret: SECRET_B, ...} }`), and stacks tracking repos in both `org_a` and `org_b`.
2. As an attacker who legitimately administers `org_a` (and thus knows `SECRET_A`), obtain the real commit SHA of a commit in a stack owned by `org_b` (visible on Shipit's public-ish UI/API or GitHub).
3. Build a `status` event payload:
```json
{
  "sha": "<org_b's real commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org_a" } }
}
```
4. Compute `X-Hub-Signature: sha1=HMAC_SHA1(SECRET_A, body)` and POST to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: 'org_a')` and validates successfully because the attacker signed with `SECRET_A`.
6. `StatusHandler#process` finds `Commit.where(sha: params.sha)` - the `org_b` commit - and calls `create_status_from_github!`, marking it `success` for `ci/required-check`, without any check that `org_a` (the signer) has any relationship to that commit's repository, potentially unlocking an unauthorized deploy on `org_b`'s stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

### Title
Webhook signature verification is scoped to the payload's `repository.owner.login`, but repository/stack resolution is scoped to `repository.full_name` — Cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on a value read out of the *same untrusted request body* it is about to verify, and the downstream event handlers then resolve the target `Repository`/`Stack` using a *different* field of that same body. In a multi-tenant Shipit deployment (multiple organizations configured under `secrets.github`), this breaks the intended binding: **organization whose secret authenticated the request == repository the request is allowed to write to**.

### Finding Description
`verify_signature` computes the org used for HMAC verification from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`), and `Shipit.github(organization: repository_owner)` looks up a **per-organization** webhook secret: [3](#0-2) 

The HMAC itself is computed over the full raw body using that organization's secret: [4](#0-3) 

However, the event handlers that actually act on the payload (e.g. resolving which `Repository`/`Stack` to write to) use a *different* JSON key, `repository.full_name`, independent of `repository.owner.login`: [5](#0-4) [6](#0-5) 

Because `verify_signature` never checks that `repository.full_name`'s owner segment matches `repository.owner.login` (the value used to pick the verifying secret), an attacker who controls (or knows the webhook secret of) **any one** organization configured on the instance can craft a raw JSON body where:
- `repository.owner.login` = their own organization (so the HMAC computed with *their* secret validates), and
- `repository.full_name` = `"victim-org/victim-repo"` (an unrelated tenant's registered stack).

The signature check passes (it only validates that the bytes were signed by the org named in `repository.owner.login`), yet the handler resolves and mutates state for `victim-org/victim-repo` via `Repository.from_github_repo_name`, `Repository.from_param!`, etc.

This is the structural analog of the M-20 report: a field that is *acted upon* (`repository.full_name`, driving which stack/repo state is written) is never cross-checked against the field that was *actually authenticated* (`repository.owner.login`, which selects the verifying secret) — an "organization that authenticated versus the repository that is written" trust binding is not enforced as an equality.

### Impact Explanation
This allows cross-repository/cross-organization writes: an attacker who is a legitimate tenant on one organization of a shared Shipit instance can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events for stacks belonging to a different organization, triggering `GithubSyncJob`, fake commit statuses, review-stack archival, or team/membership mutations for repositories they do not own. This matches the "cross-repository writes" Critical-impact category.

### Likelihood Explanation
Requires the instance to be configured with more than one GitHub organization (multi-tenant `secrets.github` config, as supported by `Shipit.github_app_config`) and requires the attacker to be an authenticated tenant of at least one of those organizations (i.e., they legitimately know/control that organization's webhook secret through their own GitHub App installation). No access to the victim organization's credentials, repository, or the Shipit UI is needed — only the ability to send a raw HTTP POST to the shared `/webhooks` endpoint with a body they can self-sign.

### Recommendation
In `WebhooksController#verify_signature`, after locating the app/secret via `repository_owner`, also assert that every repository-bearing field used downstream (`repository.full_name`, `organization.login`, etc.) resolves to the same organization that was used to select the verifying secret, and reject the request otherwise (e.g., `head(422)` if `repository.full_name.split('/').first.casecmp?(repository_owner)` fails).

### Proof of Concept
1. Deploy Shipit with two organizations configured, e.g. `secrets.github["org-a"]` (attacker-controlled) and `secrets.github["org-b"]` (victim, with a registered `Stack` for `org-b/victim-repo`).
2. Attacker knows `org-a`'s `webhook_secret` (they administer `org-a`'s GitHub App).
3. Attacker crafts a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a-secret, body)` and sends `POST /webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner == "org-a"`, fetches `org-a`'s secret, and the HMAC validates. [7](#0-6) 
6. `Shipit::Webhooks.for_event('push')` handler resolves the target repository/stack from `repository.full_name` = `"org-b/victim-repo"`, enqueuing `GithubSyncJob` for the victim's stack — despite the request never being signed by `org-b`'s secret. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

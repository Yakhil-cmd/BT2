### Title
Webhook signature verified against the payload's `repository.owner.login`/`organization.login`, but handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery in multi-org installs - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit` supports multi-organization GitHub App configuration, where each organization has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to HMAC-verify the raw request body against using `repository_owner`, which is read from the *unverified* JSON payload before the signature is checked: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) . However, the actual event handlers that mutate state (e.g. `PushHandler`, `StatusHandler`, the `PullRequest` handlers) resolve the target `Repository`/`Stack` from a *different* field in the same payload — `repository.full_name` — via `Handler#repository_name` / `Repository.from_github_repo_name` [3](#0-2) [4](#0-3) .

### Finding Description
The binding that should hold is: **organization whose secret authenticated the request == organization owning the repository the handler writes to**. Because the controller picks the verification secret from `repository.owner.login`/`organization.login` while the handlers key off `repository.full_name`, these two fields are never cross-checked against each other. A party who legitimately controls a repository/organization in a multi-tenant Shipit install (and therefore possesses a valid signature for *their own* org's webhook secret, generated either by GitHub or by replaying a signature they can compute for their own org) can craft a raw JSON body where:
- `repository.owner.login` = `"attacker-org"` (used only to pick the verification key)
- `repository.full_name` = `"victim-org/victim-repo"` (used by the handler to find the target `Stack`)

Since `verify_signature` computes the HMAC over the entire raw body using the `attacker-org` secret and that computation succeeds, the request passes signature verification even though its *effective content* (`repository.full_name`) targets a repository that belongs to a different, unrelated organization with its own distinct webhook secret [5](#0-4) . `Repository.from_github_repo_name` does not re-validate that `full_name`'s owner segment matches any authenticated identity — it simply splits the string and looks up by owner/name [4](#0-3) .

This lets an attacker who only controls one org's webhook secret forge webhook events that are processed against a *different* org's stacks, e.g.:
- `PushHandler` will trigger `stack.sync_github(expected_head_sha: ...)` for the victim's stack based on an attacker-forged `ref`/`after` [6](#0-5) .
- `StatusHandler` will create a forged commit status against the victim's tracked commit, which can be used to fabricate a green CI check that unblocks a deploy on the victim's stack [7](#0-6) .

### Impact Explanation
This breaks the cross-repository write boundary: an entity authenticated only for its own organization's webhook channel can cause state changes (sync, commit status fabrication, review-stack archive/unarchive) on stacks belonging to a different, unrelated organization/repository that never authorized it. Forged commit statuses can enable an unauthorized deploy by satisfying deploy gating logic that depends on CI status, which matches the "unauthorized deploy" high-impact category.

### Likelihood Explanation
This only manifests when a Shipit instance is configured with **multiple organizations**, each with a distinct `webhook_secret` (`secrets.github` keyed by org, per `Shipit.github_app_config`) [8](#0-7) ; the test suite even includes a `secrets_double_github_app.yml` fixture confirming this configuration is supported and exercised. In a single-org deployment (the common/default case per `github_default_organization`), there is only one secret, so this analog degrades to a no-op. It requires the attacker to hold a valid webhook secret for at least one configured organization, which is a normal, low-privilege capability in a multi-tenant install (e.g., any org admin who can generate a webhook secret for their own repo).

### Recommendation
Cross-validate that the organization used to select/verify the webhook secret matches the owner segment of `repository.full_name` (and any other repository/org identifiers used later by handlers) before dispatching to handlers, or derive both values from a single, already-verified source of truth. Reject requests where these fields diverge.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, `attacker-org` and `victim-org`, each with its own `webhook_secret` (mirrors `test/dummy/config/secrets_double_github_app.yml`).
2. Ensure a `Stack`/`Repository` exists for `victim-org/victim-repo` with a tracked commit `sha`.
3. Craft a `status` event JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(attacker-org_webhook_secret, raw_body)`.
5. POST to the webhooks endpoint with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` to `attacker-org`, verifies successfully against `attacker-org`'s secret, and `StatusHandler` then creates a fabricated `success` status on the victim's commit via `Commit.where(sha: ...).create_status_from_github!` [7](#0-6) , without ever possessing `victim-org`'s webhook secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

### Title
Webhook authentication bypass via organization/repository field confusion - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) is used to validate an inbound webhook based on an attacker-supplied field (`repository.owner.login` / `organization.login`), while the downstream handlers that actually mutate state (deploy sync, commit statuses) resolve the target repository from a *different* field in the very same JSON body (`repository.full_name`). Nothing enforces that these two fields agree, so in a multi-organization deployment an attacker can pick an organization whose `webhook_secret` is unset to trivially pass signature verification, while pointing the payload's `repository.full_name` at a victim stack that does have a secret configured.

### Finding Description
`verify_signature` picks the verification key using an attacker-controlled field before any signature has been checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves this attacker-chosen `repository_owner` string to a per-organization `GitHubApp` instance, which is exactly the mechanism documented for supporting multiple, independently-configured GitHub Apps/organizations, each with its own `webhook_secret`: [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization's `webhook_secret` is blank: [4](#0-3) 

The example/documented configuration shows `webhook_secret:` left blank/`nil` is a normal, supported state for an organization: [5](#0-4) [6](#0-5) 

Once the request passes `verify_signature` (because the attacker claimed an org with no secret), `WebhooksController#create` dispatches the *raw, attacker-controlled* payload to handlers, which never re-check the organization used for authentication — they resolve the actual repository/stack purely from `repository.full_name`: [7](#0-6) 

`PushHandler` uses that repository lookup to trigger a deploy-pipeline sync (`stack.sync_github`) using an attacker-supplied `after` SHA: [8](#0-7) 

`StatusHandler` similarly writes commit statuses purely keyed by `sha`, with no cross-check against the organization that was authenticated: [9](#0-8) 

This is the same class of bug as the reference report: a value (`repository.owner.login`/`organization.login`, used for the trust decision) is not bound to the value that is actually acted upon (`repository.full_name`), and no cryptographic binding forces the two to be consistent, because the whole request body is attacker-forged prior to signature validation. The equality that should hold — `organization authenticated == repository/organization written` — does not, because the signature only proves *some* configured secret (possibly none) matches, not that it matches the org whose data is mutated.

### Impact Explanation
An attacker who can identify (or simply try) any organization key in the engine's multi-org GitHub configuration that has no `webhook_secret` set can forge arbitrary `push`, `status`, `check_suite`, `membership`, etc. events for any tracked stack/repository in the installation, because verification passes trivially for that org while the acted-upon repository is taken from an unrelated payload field. This enables unauthorized deploy-pipeline synchronization, forged commit statuses (which can gate `deployable_status`/merge decisions), and forged team/membership changes — all without any credential, session, or API token. This matches the "cross-repository writes" / "unauthorized deploy, rollback or merge" Critical impact bucket.

### Likelihood Explanation
Requires only network access to the public `/webhooks` endpoint and knowledge that one organization entry in a multi-org `github:` configuration has a blank `webhook_secret` (a state explicitly shown as valid/default in the shipped example config files). No authentication, session, or GitHub-side write access is needed.

### Recommendation
Enforce a single authenticated identity per request: verify the webhook signature using the secret associated with the repository/organization that the handlers will actually act on (`repository.full_name`'s owner), not a separately-derived `repository_owner` field, and reject requests where the two disagree. Additionally, consider rejecting webhooks outright when the resolved organization has no configured `webhook_secret`, rather than treating a blank secret as an automatic pass.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `victim-org` (has `webhook_secret: s3cr3t`, tracks stack `victim-org/app`) and `empty-org` (no `webhook_secret` configured), per the documented multi-org schema.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "organization": { "login": "empty-org" },
  "repository": { "full_name": "victim-org/app", "owner": { "login": "empty-org" } },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required.
3. `repository_owner` resolves to `empty-org`; `Shipit.github(organization: 'empty-org')` returns the app config with a blank `webhook_secret`; `verify_webhook_signature` returns `true` unconditionally.
4. `PushHandler#repository_name` reads `repository.full_name` = `victim-org/app`, locates the real victim stack, and calls `stack.sync_github(expected_head_sha: <attacker sha>)`, triggering pipeline logic for a repository/org the attacker never authenticated against.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-14)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

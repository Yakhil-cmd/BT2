Confirmed: `handler.rb`'s `repository_name` derives from `payload.dig('repository', 'full_name')`, which is entirely independent of the `repository_owner` value (`params.dig('repository', 'owner', 'login')`) used by `WebhooksController#verify_signature` to select which organization's `webhook_secret` validates the HMAC. `GitHubApp#verify_webhook_signature` explicitly no-ops (`return true unless webhook_secret`) when the selected organization has no secret configured — a supported, undocumented-as-dangerous configuration shown even in this repo's own `test/dummy/config/secrets.test.json` (`"webhook_secret": null`) and `config/secrets.development.shopify.yml` templates.

### Title
Webhook signature is bound to `repository.owner.login`/`organization.login` while event handlers act on the independent `repository.full_name` field, allowing cross-repository event injection when any configured organization has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App config (and thus the HMAC secret) to validate against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`. The actual event-processing code (`Shipit::Webhooks::Handlers::Handler#repository_name`) looks up the target `Repository`/`Stack` using an entirely different, unrelated field: `payload.dig('repository', 'full_name')`. Because `verify_webhook_signature` is a no-op when the selected organization has no `webhook_secret` configured (`return true unless webhook_secret`), an attacker can craft a payload where `repository.owner.login`/`organization.login` names an organization with no secret (bypassing verification entirely) while `repository.full_name` points at a completely different, secret-protected repository/stack. The signature check therefore verifies the wrong binding: it authenticates "did this come from an org with no secret" rather than "is this event legitimately about the repository the handlers will act on."

### Finding Description [1](#0-0) 

Signature verification organization selection: [2](#0-1) 

`verify_webhook_signature` treats an unset `webhook_secret` as automatically verified: [3](#0-2) 

Meanwhile, the dispatched event handlers resolve the target repository from a completely different payload field: [4](#0-3) 

and, e.g., the push handler syncs stacks for that resolved repository based on attacker-controlled `ref`/`after`: [5](#0-4) 

Multiple GitHub Apps/organizations can be configured simultaneously, each with independent `webhook_secret` (some legitimately left blank in examples/tests): [6](#0-5) [7](#0-6) 

The binding that should hold is: `organization whose webhook_secret authenticated the request == owner of the repository whose Stack/Commit/Status state is mutated by the handler`. Because these two are read from independently-controllable JSON fields, and because `webhook_secret` is optional per-organization (falling back to "always verified"), that equality is never enforced — an attacker only needs the request to be attributable (via `repository.owner.login`/`organization.login`) to any one configured organization that has no secret, while `repository.full_name` can name any other repository/stack tracked by the Shipit instance, whose data (commit statuses, check runs, membership, pushes triggering `sync_github`) will be mutated.

### Impact Explanation
This breaks an authentication boundary the engine relies on to trust inbound webhook data: `push`, `status`, `check_suite`, and `membership` events control `Commit#statuses`, triggers `GithubSyncJob`/`stack.sync_github`, and (per `test/controllers/webhooks_controller_test.rb`) can create/delete `Team` and `Membership` records that feed directly into `Shipit.github_teams` authorization (`User#authorized?`). An attacker exploiting the no-secret organization can forge these events for any repository tracked by the instance — this maps to "escalation into `Shipit.github_teams` authorization" (membership forgery) and "unauthenticated read of stack state" (spurious sync/status injection triggering deploy-adjacent state changes) — both explicitly listed High-severity impacts.

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one configured GitHub organization/app with `webhook_secret` unset — which the engine's own shipped example configs (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets.test.json`) demonstrate as an accepted, non-error configuration. Any installation using the "Multiple GitHub Applications" feature with even one org lacking a webhook secret (e.g., an app added for OAuth/team-restriction purposes only, without webhook delivery configured) is exposed to unauthenticated cross-repository webhook injection with zero credentials required.

### Recommendation
Bind signature verification to the same repository object the handlers act on: derive the verifying organization from `repository.full_name`'s owner segment (not a separate `owner.login`/`organization.login` field), and reject events where `repository.full_name`'s owner does not match `repository.owner.login`/`organization.login`. Additionally, do not silently treat a missing `webhook_secret` as "verified" — either require a secret for every configured organization or reject/flag deliveries for secret-less orgs.

### Proof of Concept
1. Deploy Shipit with two GitHub organizations configured under `secrets.github`: `noSecretOrg` (no `webhook_secret`) and `victimOrg` (has `webhook_secret`, hosts a tracked repository `victimOrg/secret-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and any/no `X-Hub-Signature`, body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "noSecretOrg" },
       "full_name": "victimOrg/secret-repo"
     }
   }
   ```
3. `verify_signature` computes `repository_owner = "noSecretOrg"`, loads its `GitHubApp`, and `verify_webhook_signature` returns `true` unconditionally since `webhook_secret` is blank — no valid signature is required.
4. `Shipit::Webhooks::Handlers::PushHandler` resolves `repository_name` from `payload.dig('repository','full_name')` = `"victimOrg/secret-repo"`, and calls `stack.sync_github(expected_head_sha: ...)` on stacks belonging to that repository, despite the request never being validated against `victimOrg`'s secret. [8](#0-7) [3](#0-2) [9](#0-8)

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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

**File:** test/dummy/config/secrets.test.json (L1-21)
```json
{
  "host": "shipit.com",
  "secret_key_base": "s3cr3ts3cr3ts3cr3ts3cr3ts3cr3ts3cr3t",
  "github_api": {
    "token": "t0k3n"
  },
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
    "oauth": {
      "id": "Iv1.bf2c2c45b449bfd9",
      "secret": "ef694cd6e45223075d78d138ef014049052665f1",
      "teams": null
    }
  },
  "redis_url": "redis://127.0.0.1:6379/7"
}
```

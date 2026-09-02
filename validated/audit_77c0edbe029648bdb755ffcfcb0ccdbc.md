### Title
Webhook signature verification selects the GitHub App/secret from an unverified `repository.owner.login`/`organization.login` field, decoupling the authenticated organization from the repository actually acted upon — allowing forged CI statuses / pushes across repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which organization's webhook secret to verify a payload against by reading `repository.owner.login` (falling back to `organization.login`) directly from the **unverified** JSON body, before any cryptographic check has occurred. [1](#0-0) [2](#0-1)  Downstream handlers, however, resolve the target repository/commit from a *different* field of the same attacker-authored payload (`repository.full_name` for most handlers, or nothing at all for `StatusHandler`). [3](#0-2) [4](#0-3)  Because Shipit supports one instance shared across several independently-configured GitHub organizations, each with its own `webhook_secret`, [5](#0-4)  an attacker who legitimately administers one onboarded organization (and therefore genuinely knows that organization's `webhook_secret`) can craft a payload where the field used for signature-org-selection names *their own* org, while the field(s) used to pick the actual repository/commit to mutate name a **victim** org/repo they do not control.

### Finding Description
`verify_signature` is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

`Shipit.github(organization: ...)` resolves to a `GithubApp` instance carrying that specific organization's `webhook_secret`, and `verify_webhook_signature` computes an HMAC over the raw body using **that** secret. [7](#0-6)  The HMAC binds the payload bytes to *a* secret, but nothing binds "the organization whose secret validated this request" to "the organization/repository the payload claims to be about." Since the attacker fully controls the raw JSON body (and thus can set `repository.owner.login` to their own org while independently setting `repository.full_name` or `sha` to reference an unrelated victim resource), they can produce a body that is genuinely, correctly signed with their own known secret yet is processed by handlers as if it originated from a different repository/org.

This is exploitable most severely via `StatusHandler`, which does not check repository ownership at all — it looks up commits purely by SHA across the entire instance:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [8](#0-7) 

Other handlers (`PushHandler`, pull-request handlers) at least re-derive the target repository from `repository.full_name` in the same payload [9](#0-8) [3](#0-2) , but since that field is just as attacker-controlled as `repository.owner.login`, it is not a meaningful protection: the attacker can equally set it to a victim's `full_name`.

The bug-class analog to the `USDLStrategy._swapPLSforUSDL()` report is direct: just as `amountOutMin` is computed from an on-chain value the transaction itself does not attest to be trustworthy (manipulable reserves), here the security-critical routing decision (which org's secret legitimises this request) is computed from a payload field that is not bound to the field the privileged action actually consumes (the repository/commit acted on). The equality that should hold — `organization authenticated == organization whose repository is written` — is broken because both sides are read from the same untrusted, attacker-supplied document with no cryptographic linkage between them.

### Impact Explanation
An attacker who is a legitimate, unprivileged administrator of any GitHub organization onboarded to a shared multi-org Shipit deployment can:
- Forge `status` webhook payloads that flip CI status to `success` for arbitrary commit SHAs belonging to **other** organizations'/repositories' stacks on the same instance, bypassing CI gating and enabling Shipit's continuous-deployment logic to trigger an unauthorized deploy of a repository they have no access to, or
- Forge `push` events naming a victim repository's `full_name`, causing Shipit to resync/react to attacker-chosen `ref`/`after` values for stacks they do not own.

This crosses the "unauthorized deploy" / "cross-repository writes" impact bar entirely from the unprivileged position of controlling an unrelated organization's webhook secret — no Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required.

### Likelihood Explanation
Requires the deployment to be configured for multiple GitHub organizations sharing one Shipit instance (an explicitly documented/supported configuration, see `config/secrets.development.shopify.yml` and `docs/setup.md`). [5](#0-4)  Given that configuration, exploitation only requires knowledge of one's own legitimately-configured `webhook_secret` and the ability to send an arbitrary HTTP POST to the shared webhook endpoint — no special access to the victim org is needed.

### Recommendation
Do not use unauthenticated payload fields to select the verification secret. Instead, verify the signature against every configured organization's secret (or use a per-organization webhook endpoint / a `X-GitHub-Hook-Installation-Target-ID` mapping trusted independently of the JSON body) and reject the payload unless the organization that validated the signature matches the organization owning the repository referenced by the payload. Additionally, `StatusHandler` should validate that the resolved commit's stack repository belongs to the same organization that produced a validating signature before applying `create_status_from_github!`.

### Proof of Concept
1. Attacker legitimately owns/administers GitHub organization `attacker-org`, which is configured in this shared Shipit instance with its own known `webhook_secret_attacker`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-commit-sha-visible-in-shipit>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/irrelevant" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_attacker, body)` and POSTs to `/github/webhooks`.
4. `repository_owner` resolves to `attacker-org`, `Shipit.github(organization: 'attacker-org')` yields the attacker's own `GithubApp`, and `verify_webhook_signature` succeeds because the HMAC matches their own known secret. [10](#0-9) 
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` with no repository/organization scoping and creates a `success` status for the victim's commit, regardless of which repository it actually belongs to. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

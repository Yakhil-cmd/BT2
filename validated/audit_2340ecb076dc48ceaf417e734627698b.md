### Title
Webhook authentication binds to `repository.owner.login`/`organization.login` while push/status/check_suite handlers act on the independent `repository.full_name` field — cross-organization webhook forgery in multi-tenant configuration - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-org Shipit deployment, each GitHub organization is configured with its own `webhook_secret` [1](#0-0) . The controller selects *which* org's secret to verify the HMAC signature against using `repository_owner`, computed from `params.dig('repository','owner','login')` or `params.dig('organization','login')` [2](#0-1) . However, the event handlers that actually perform the write (finding/syncing a `Stack`) select the target repository using a **different**, independently-controlled JSON field: `payload.dig('repository', 'full_name')` [3](#0-2) [4](#0-3) . Nothing enforces that `repository.owner.login` (used for authentication) is consistent with `repository.full_name` (used for the write).

### Finding Description
The binding that should hold is:
`organization whose secret authenticated the signature == owning organization of the repository whose stack gets written`

Before the attacker's request: an org "attacker-org" onboarded onto this Shipit instance knows and controls its own `webhook_secret` (it is an org-specific application secret, not a Shipit session/API token, and not the target org's secret). `secrets.github` holds an entry per org, each independently readable/writable/settable by that org's own GitHub App admin [5](#0-4) .

`Shipit::GitHubApp#verify_webhook_signature` only checks the HMAC of the raw body against the secret for whichever organization `verify_signature` picked [6](#0-5) ; it never checks that the org used to select the secret matches the org that will actually be operated on:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

After the attacker's request: the attacker crafts a raw JSON body where `repository.owner.login` = `"attacker-org"` (so the signature validates using attacker-org's own known secret) but `repository.full_name` = `"victim-org/victim-repo"`. Since these are two unrelated JSON keys in the same object, nothing forces them to agree. The signature check passes because it is genuinely a valid HMAC computed by the attacker using their own legitimate secret over a payload they fully control.

`Shipit::Webhooks.for_event('push')` then dispatches to `PushHandler`, whose `stacks` method resolves the target purely from `repository.full_name`:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [7](#0-6) 

This lets the request act on `victim-org/victim-repo`'s stacks even though the signature was validated against `attacker-org`'s secret, breaking the intended organization-repo binding. The same pattern applies to `status` and `check_suite` handlers, which also key off `repository.full_name`.

### Impact Explanation
This is a cross-organization write: an entity that only legitimately controls one tenant's GitHub App/webhook secret can trigger `GithubSyncJob`/`RefreshCheckRunsJob`/commit `Status` writes against a stack belonging to a completely different, unrelated organization/repository it has no access to. Depending on `stack.sync_github` behavior (fetching git refs, updating commit records used later for deploy eligibility) and CI status spoofing via the `status` event, this can be leveraged to poison commit metadata or force sync of commits controlling deployability (`Commit#deployable?`), i.e., an unauthorized influence over deploy/rollback eligibility for a repository/organization the attacker doesn't own — meeting the "cross-repository writes" / "unauthorized deploy" impact bar. It requires no Shipit session, API token, or privileged Shipit account — only knowledge of a secret the attacker legitimately owns for their own tenant.

### Likelihood Explanation
Requires a multi-tenant `secrets.github` configuration (explicitly documented/supported schema) where multiple organizations' GitHub Apps point at the same Shipit instance [1](#0-0) . Any onboarded organization admin (an "unprivileged attacker" relative to other tenants) can exploit this by crafting a raw POST directly to `/webhooks` — no GitHub interaction needed, since only the raw body + a valid HMAC (computable by the attacker with their own secret) is required.

### Recommendation
After signature verification, re-derive the organization from the *same* field(s) that the handlers use to select the write target (`repository.full_name`'s owner segment, or an explicit lookup of `Repository`→its configured org/app), and reject the request if it doesn't match the organization whose secret validated the signature. Alternatively, bind `verify_signature` and all handlers to a single canonical field (e.g., always derive org from `repository.full_name.split('/').first`) so the field authenticated is identical to the field acted upon.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` (secret `S_A`) and `victim-org` (secret `S_V`), each with a `Repository`/`Stack` registered.
2. Attacker builds a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` using their own known secret `S_A`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `S_A`, and the HMAC validates successfully [8](#0-7) .
6. `PushHandler#stacks` resolves stacks via `repository.full_name = "victim-org/victim-repo"`, and triggers `stack.sync_github` on victim-org's stack [7](#0-6)  — despite the request never being authenticated with `victim-org`'s secret.

### Citations

**File:** config/secrets.development.example.yml (L18-30)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
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

### Title
Webhook signature verification is keyed by the attacker-controlled `repository.owner.login` field while event handlers act on the independently-controlled `repository.full_name` field, allowing cross-organization webhook forgery when multi-org configs contain any organization without a `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate the incoming signature against based on `repository.owner.login` parsed out of the *unverified* raw JSON body. [1](#0-0) [2](#0-1) 
Once verification "passes," the full raw `params` (including a completely independent `repository.full_name` field) are handed to the event handlers, which use `repository.full_name` to resolve which `Repository`/`Stack` to act on via `Repository.from_github_repo_name`. [3](#0-2) [4](#0-3) [5](#0-4) 

Nothing binds these two fields together cryptographically or structurally — the signature only proves the payload came from whichever org `repository.owner.login` names, not that `repository.full_name` belongs to that same org.

### Finding Description
`verify_signature` computes `repository_owner` from the payload itself and uses it to fetch the `GitHubApp` used for HMAC verification:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that org:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [7](#0-6) 

The multi-org secrets schema explicitly supports per-organization config, and it is normal/documented for an org entry to have `webhook_secret: nil` (seen in the fixture `OrgTwo`). [8](#0-7) 
`Shipit.github_app_config` resolves whichever org name the attacker supplies, case-insensitively, as long as it's a configured key. [9](#0-8) 

After `verify_signature` succeeds (whether because the real secret matched, or because the selected org has no secret at all), `create` parses the raw body and passes the *entire* payload — unmodified — to the event handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  ...
end
``` [3](#0-2) 

Handlers never re-check `repository.owner.login`; they resolve the target `Repository`/`Stack` purely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 
`PushHandler`, PR handlers, etc. all follow this pattern, driving `stack.sync_github`, PR archive/unarchive/provisioning actions, etc. [10](#0-9) [11](#0-10) 

The binding that is broken: **the organization whose signature was authenticated (`repository.owner.login`) ≠ the repository whose stack actions are executed (`repository.full_name`)**. If a Shipit deployment configures multiple GitHub orgs and any one of them lacks a `webhook_secret` (a legitimately supported, documented configuration — an org can be onboarded without a secret, or a secret can be blank during setup), an unauthenticated attacker can craft a webhook body where `repository.owner.login` is set to that secret-less org (making `verify_webhook_signature` return `true` unconditionally) while `repository.full_name` names a *different*, properly protected org's repository/stack. The forged request sails through `verify_signature` and is then fully processed against the victim stack.

### Impact Explanation
This is an authentication-bypass class issue: it lets an unauthenticated network attacker forge GitHub webhook events (push, pull_request open/close/label, membership, etc.) against any stack belonging to a properly-secured organization, as long as some other configured org in the same Shipit instance has no `webhook_secret`. Concretely this enables triggering `stack.sync_github` (push handler), and manipulating review-stack provisioning/archival/label state for PR handlers — actions that should require a legitimate, signed GitHub webhook. This maps to the "escalation into unauthorized deploy/rollback-adjacent state changes" / "unauthenticated action against protected stack" impact bucket.

### Likelihood Explanation
Requires: (1) a Shipit deployment using the multi-organization github secrets schema, and (2) at least one configured organization with a blank/missing `webhook_secret` (a state explicitly modeled and tested in this codebase's own fixtures, `test/dummy/config/secrets_double_github_app.yml`, and not flagged as invalid config anywhere). No credentials, tokens, or privileged access are needed — the webhook endpoint is unauthenticated by design and only relies on the HMAC check this bug undermines.

### Recommendation
Bind the field used to select the verifying `GitHubApp`/secret to the same field the handlers use to resolve the target repository (`repository.full_name`'s owner segment), or verify the payload against every configured org's secret and require that the org that authenticates the signature match the owner of `repository.full_name` before dispatching to handlers. Additionally, treat a missing `webhook_secret` for a configured multi-org entry as a hard misconfiguration (raise/refuse) rather than silently returning `true`, since it currently makes that org (and, via this owner/full_name mismatch, potentially any other org) unauthenticated.

### Proof of Concept
1. Deploy Shipit with a multi-org `secrets.github` config where `OrgTwo.webhook_secret` is blank/nil (as in `test/dummy/config/secrets_double_github_app.yml`) and `OrgOne` has a real `webhook_secret` protecting a tracked stack, e.g. `orgone/protected-repo`.
2. POST to `/webhooks` (per `config/routes.rb`) with header `X-Github-Event: push` and no valid `X-Hub-Signature` for `OrgOne`, and body:
```json
{
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "orgone/protected-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` computes `repository_owner = "OrgTwo"`, calls `Shipit.github(organization: "OrgTwo")`, whose `verify_webhook_signature` returns `true` unconditionally because `OrgTwo.webhook_secret` is nil.
4. `create` dispatches the full payload to `PushHandler`, which resolves the stack via `repository.full_name = "orgone/protected-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the protected `OrgOne` stack — with no valid signature ever having been presented for `OrgOne`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-47)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

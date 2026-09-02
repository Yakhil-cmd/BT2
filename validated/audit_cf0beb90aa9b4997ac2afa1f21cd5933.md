### Title
Webhook signature verification authenticates the claimed GitHub organization but the event handlers act on an attacker-controlled repository field from the same unauthenticated payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). Once the signature check passes for that organization, every `Shipit::Webhooks::Handlers::Handler` subclass resolves the target `Repository`/`Stack` using a *different* field from that same untrusted body: `payload.dig('repository', 'full_name')`. Nothing ties the two fields together, so a caller who can get a valid signature for organization A (e.g. because that organization has no `webhook_secret` configured, which `verify_webhook_signature` explicitly treats as "always valid") can supply a `repository.full_name` belonging to a completely different, unrelated organization/repository that is registered in the same Shipit instance, and have the handler act on it.

### Finding Description
The controller performs authentication at the *organization* granularity: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`verify_webhook_signature` explicitly no-ops when the organization has no secret configured: [2](#0-1) 

`webhook_secret` is documented as an optional field (the shipped example config even ships it commented "# nil"): [3](#0-2) 

Once this check passes, every handler resolves the *repository being acted on* from an independent field of the same JSON body, never re-checked against `repository_owner`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

This pattern repeats across every PR/push/status handler (`PushHandler`, `StatusHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, etc.), all of which key their side effects off `params.repository.full_name`: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that is supposed to hold is:
`organization authenticated by verify_signature (repository_owner) == organization that owns the repository/stack mutated by the handler (repository.full_name)`

This equality is never enforced. Before the request: attacker has no relationship whatsoever to the target repository/stack. After the request: the attacker has caused Shipit to fetch commits, create statuses, or archive/unarchive review stacks for a repository/stack outside of the organization that was actually authenticated - this is exactly the "organization that authenticated versus the repository that is written" binding class called out in the task rules, and mirrors C‑01's root cause: a verification step (`totalUnstaked`/signature) is scoped to one identifier while the state actually mutated is keyed by another, unrelated identifier (`peerId`/`repository.full_name`) that the caller fully controls.

### Impact Explanation
Because `Handler#stacks`/`#repository_name` is shared by every webhook handler, an attacker who can pass `verify_signature` for any one configured organization (trivial if that organization has no `webhook_secret` set, which is a documented, legitimate configuration state) can direct arbitrary handler side effects at *any other* repository/stack registered in the same Shipit instance:
- `PushHandler` invokes `stack.sync_github(expected_head_sha:)` for a foreign stack, forcing Shipit to re-sync commits from GitHub and enqueue `CacheDeploySpecJob` for it.
- `StatusHandler` injects a forged commit status (`create_status_from_github!`) that CI-gated deploy/merge logic elsewhere in Shipit may rely on.
- `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler` can create, archive, or unarchive review stacks belonging to a foreign repository.

This is a cross-repository/cross-organization write against Shipit's own state model, performed by a caller with no legitimate relationship to the affected repository, satisfying the "cross-repository writes" High/Critical impact bucket in the rules.

### Likelihood Explanation
High for any deployment using the documented "Using Multiple Github Applications" multi-tenant configuration (`docs/setup.md`) where at least one onboarded organization omits `webhook_secret` (an explicitly supported, documented state) - no credentials, sessions, or private keys are needed at all in that case. Even where every organization sets a secret, any tenant that legitimately controls one organization's own webhook secret can still cross into another tenant's repositories, since the two fields are never cross-validated.

### Recommendation
After `verify_signature` succeeds for `repository_owner`, every handler must re-derive/re-validate the target `Repository` against that same authenticated organization (e.g. pass the authenticated organization into `Handler.call`/`Handler#initialize` and require `repository.owner.downcase == authenticated_organization.downcase` before resolving `stacks`), rather than trusting `repository.full_name` from the unauthenticated body in isolation.

### Proof of Concept
1. Configure Shipit in multi-organization mode with two tenants: `OrgA` (attacker-controlled or with `webhook_secret` unset) and `OrgB` (victim, hosts a real registered `Stack` for `OrgB/victim-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
Optionally with a valid `X-Hub-Signature` computed using `OrgA`'s own webhook secret (or no signature at all if `OrgA` has none configured).
3. `verify_signature` calls `Shipit.github(organization: "OrgA")` and succeeds, because it only checks the signature against `OrgA`'s configuration.
4. `PushHandler#process` (via `Handler#repository_name`) resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and invokes `stack.sync_github(expected_head_sha: ...)` on the victim's stack, despite the request only having been authenticated for `OrgA`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-17)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

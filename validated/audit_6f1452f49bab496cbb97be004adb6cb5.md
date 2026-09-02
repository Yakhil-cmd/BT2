### Title
Webhook signature verified against the organization named in the unverified payload, while the repository the handler writes to is taken from that same unverified payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the still‑unauthenticated request body. The handler that subsequently processes the event (e.g. `PushHandler`) resolves the target `Stack`/`Repository` from `repository.full_name`, also taken from that same unauthenticated body. Nothing binds "the organization whose secret validated the signature" to "the repository/stack that is actually mutated." If a multi‑organization Shipit deployment has any organization configured with no `webhook_secret` (documented as optional in `docs/setup.md`), `verify_webhook_signature` short-circuits to `true` for any payload claiming that organization, letting an attacker forge events (push, status, membership, pull_request, etc.) that reference an arbitrary *other* organization's repository/stack.

### Finding Description
`verify_signature` computes `repository_owner` from the raw JSON body before any cryptographic check is performed: [1](#0-0) [2](#0-1) 

That attacker-controlled `repository_owner` value is used to pick the `GitHubApp` instance to verify the signature with: [3](#0-2) 

and `verify_webhook_signature` unconditionally returns `true` when the selected organization has no `webhook_secret` configured: [4](#0-3) 

Once verification passes (trivially, because no secret exists for the org named in the payload), `WebhooksController#create` dispatches the event to the registered handler using the *same unauthenticated* payload: [5](#0-4) 

Handlers such as `PushHandler` resolve the affected `Stack` purely from `repository.full_name` in that payload, independent of the `repository.owner.login`/`organization.login` value that was used for signature selection: [6](#0-5) [7](#0-6) 

This breaks the binding: `organization that authenticated == repository that is written`. In a single-organization deployment this is not exploitable because there is only one possible verification target. But `Shipit.github_organizations` and `github_app_config` explicitly support multiple organizations configured under `secrets.github` simultaneously: [8](#0-7) 

If any one of those configured organizations has a blank/absent `webhook_secret` (explicitly documented as "optional" in `docs/setup.md`), an attacker can craft a payload where `repository.owner.login` (or `organization.login`) names that low-security organization while `repository.full_name` names a stack that actually belongs to a different, properly-secured organization on the same Shipit instance. `verify_webhook_signature` will pass (secretless org), and the handler will act on the victim organization's repository/stack using data entirely controlled by the attacker.

### Impact Explanation
This crosses a repository/authentication trust boundary that this engine is responsible for enforcing: an unauthenticated actor can trigger repository-scoped side effects — forcing `GithubSyncJob`/`sync_github` on an arbitrary stack via forged `push` (`PushHandler`), injecting `Status`/`Commit` state via forged `status` events, creating `Team`/`Membership`/`User` records via forged `membership` events, or driving `merge`/`pull_request` handlers — for a repository they were never authorized to send webhooks for, as long as any organization in the multi-tenant configuration lacks a webhook secret. This matches the "cross-repository writes" / "unauthorized deploy" criteria: forged push events can trigger sync/deploy pipelines against a repository the attacker does not control.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with multiple GitHub organizations via `secrets.github`, and (2) at least one of those organizations configured without a `webhook_secret` (explicitly allowed, and documented as optional, so realistic for a staging/sandbox org added alongside a production org). Given that condition, exploitation requires only sending a crafted, unsigned/arbitrarily-signed HTTP POST to the public `/webhooks` endpoint — no credentials, session, or GitHub App key needed.

### Recommendation
Bind the verified organization to the repository being acted upon: after establishing the GitHub App used for verification, confirm that the `repository.full_name` (or `organization.login`) actually belongs to that same verified organization (e.g., compare `repository.owner.login` used for verification against the owner segment of `repository.full_name`, and reject mismatches) rather than trusting `repository.full_name` unconditionally in `Handler#repository_name`. Additionally, consider requiring a non-blank `webhook_secret` for every configured organization, or verifying against all configured secrets rather than a single one selected from unauthenticated data.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `victim-org` (with `webhook_secret` set) and `sandbox-org` (with no `webhook_secret`, i.e. omitted per the "optional" doc guidance).
2. Send `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "sandbox-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No `X-Hub-Signature` (or any arbitrary value) is required.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'sandbox-org')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb` line 77).
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves stacks via `Repository.from_github_repo_name('victim-org/victim-repo')` (`app/models/shipit/webhooks/handlers/handler.rb` line 33) and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — despite the request never being authenticated by `victim-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

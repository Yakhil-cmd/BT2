### Title
Webhook signature verification selects its trust anchor from the same unverified payload it is supposed to authenticate - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` decides *which* GitHub App / webhook secret to verify a request against by reading `repository_owner` straight out of the still-unverified JSON body, and `GitHubApp#verify_webhook_signature` silently treats a missing secret as "verified". Because the value used to select the trust anchor and the value later used to determine which `Stack`/`Repository` is acted upon both come from the same attacker-supplied payload, an attacker can pick an organization key that has no `webhook_secret` configured to make Shipit accept an unsigned, forged webhook and dispatch it to the normal event handlers.

### Finding Description
`WebhooksController#verify_signature` parses `repository_owner` from `params` (built from `request.raw_post`, i.e. attacker-controlled, unverified body) *before* any signature check has succeeded: [1](#0-0) [2](#0-1) 

That value is used to pick which per-organization `GitHubApp` config (and therefore which `webhook_secret`) is used for verification: [3](#0-2) 

`GitHubApp#verify_webhook_signature` unconditionally returns `true` when the resolved org has no `webhook_secret` configured: [4](#0-3) 

A blank/`nil` `webhook_secret` per organization is a documented, supported configuration state (multi-tenant secrets file shows it explicitly): [5](#0-4) 

Once `head(422)` is *not* triggered, the controller hands the raw, attacker-controlled `params` to every registered handler for the event, with no re-binding to the organization that "authenticated" the request: [6](#0-5) 

Handlers such as `PushHandler` locate and mutate `Stack` records purely from the payload's own `branch`/`repository` data, independent of which org key gated the signature check: [7](#0-6) 
and `Repository.from_github_repo_name`/`from_param!` resolve stacks purely from `owner`/`name` strings taken from the request: [8](#0-7) 

This breaks the intended binding: `organization that authenticated the webhook == organization/repository that gets written to`. In this engine, both sides of that equality are computed from the same untrusted payload, and the "authentication" side degrades to a no-op whenever any configured organization omits its `webhook_secret`.

### Impact Explanation
On a multi-tenant Shipit install (the engine explicitly supports per-organization GitHub Apps via `Shipit.github_organizations`/`github_app_config`), if even one configured organization has no `webhook_secret` set (a state the shipped config templates present as normal/optional), any unauthenticated party on the internet can POST a crafted JSON body to `/webhooks` with `repository.owner.login` set to that organization and the event type/payload of their choosing. `verify_signature` will resolve that org, find no secret, and return `true`, and the forged event will then be processed by the real handlers (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.), letting the attacker trigger `GithubSyncJob`, drive continuous-delivery syncing, forge commit statuses, or manipulate merge-queue/PR state for stacks under that repository — all without ever presenting a valid GitHub-issued signature. This is an authentication-bypass on the sole boundary meant to prove a webhook actually originated from GitHub, and downstream effects can include unauthorized deploy triggers for `continuous_deployment` stacks.

### Likelihood Explanation
The binding break requires no credentials, no TLS interception, and no host misconfiguration beyond a configuration state (blank `webhook_secret` for one org) that the engine's own templates present as valid. Any operator running Shipit with more than one GitHub App configured, where not every one has a secret set, is exposed purely through crafting an HTTP POST — this is directly reachable by an unauthenticated attacker.

### Recommendation
Do not let the organization/repository claimed inside the unverified payload determine whether signature verification is skipped. Require every configured organization to have a non-blank `webhook_secret` (fail closed, not `return true unless webhook_secret`), and/or verify the signature against every configured secret rather than one selected by attacker-supplied data, only proceeding to dispatch handlers for the organization whose secret actually validated the payload.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `orgA` (no `webhook_secret`) and `orgB` (with a `webhook_secret`), each with repos under Shipit's control (mirrors the shipped template at `config/secrets.development.shopify.yml`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and a body such as:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/some-repo" }
}
```
No `X-Hub-Signature` header is required.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally.
4. `PushHandler#process` runs against `Stack`s under `orgA/some-repo`, invoking `stack.sync_github(expected_head_sha: "deadbeef")` with no valid GitHub signature ever presented, demonstrating unauthenticated triggering of engine behavior meant to be gated by webhook authenticity.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

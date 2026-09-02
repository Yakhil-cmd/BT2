### Title
Webhook signature is verified against `repository.owner.login`, but the write path uses the independently-parsed `repository.full_name` - cross-repository forged webhook writes ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GithubApp`/webhook secret to validate an inbound webhook HMAC using one field parsed out of the JSON body (`repository.owner.login`, falling back to `organization.login`), while every webhook handler that actually performs the write (creating commits, statuses, memberships, etc.) resolves the target `Stack`/`Repository` from a *different* field parsed independently out of the same body (`repository.full_name`). Nothing in the code enforces that these two independently-extracted fields refer to the same repository, so a request can be crafted where the "authenticating" field points at an organization the attacker legitimately controls (and thus can sign for) while the "acted-upon" field points at any other repository configured on the same Shipit instance.

### Finding Description
`verify_signature` computes the authenticating organization purely from payload contents: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns a `GithubApp` instance configured (per-organization) with its own `webhook_secret`, and the HMAC is verified with that specific secret over the raw body: [3](#0-2) 

The `organization:` parameter is a first-class, per-organization concept throughout the engine (`TOP_LEVEL_GH_KEYS`, `GithubOrganizationUnknown`, and repeated `Shipit.github(organization: owner)` calls in `Repository#github_app`), confirming that multiple organizations with distinct webhook secrets are a supported, real deployment configuration: [4](#0-3) [5](#0-4) 

Once the signature check passes, `Handler#process` is invoked with the raw parsed payload. Every handler determines *which* stack/repository is being acted upon by re-parsing the body independently, using `repository.full_name` — not the `repository.owner.login` field that was used for authentication: [6](#0-5) [7](#0-6) 

`PushHandler`, for example, uses this to look up stacks and immediately triggers a resync with an attacker-controlled `after` SHA: [8](#0-7) [9](#0-8) 

This is exactly the class of bug in the report: two computations that are supposed to represent "the same repository" are derived independently from the same input via different fields/paths (`owner.login` vs `full_name`), and the code assumes they always agree. GitHub itself always keeps them consistent, but nothing in Shipit enforces it, so a forged payload can decouple them.

**Binding broken:** organization that authenticated (`repository.owner.login` / `organization.login`, verified against a specific org's `webhook_secret`) ≠ repository that is written (`repository.full_name`, used to resolve the `Stack`/`Repository` acted upon by the handler).

### Impact Explanation
An attacker who legitimately controls one GitHub organization/repository configured on a shared, multi-tenant Shipit instance (and therefore legitimately knows or can obtain that organization's own `webhook_secret`, e.g. as the org's GitHub App admin) can forge a webhook whose `repository.owner.login`/`organization.login` matches their own org (so it authenticates successfully with their own secret) but whose `repository.full_name` names an arbitrary *other* repository hosted on the same instance. The corresponding handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, PR handlers, etc.) will then act on the victim stack: e.g. `PushHandler` forces a `GithubSyncJob` to run and record commits/state against the victim's stack using an attacker-chosen `after` SHA. This is a cross-repository write performed by a party with no privileges on the target repository, satisfying the Critical "cross-repository writes" bar.

### Likelihood Explanation
The attack requires: (1) a Shipit instance configured for more than one GitHub organization (a supported and documented configuration — `github.webhook_secret` is set per organization/app), and (2) the attacker controlling one such organization's webhook secret, which is routine for any organization admin who set up their own GitHub App/webhook integration on the shared instance. No GITHUB_TOKEN, ApiClient token, or the target org's secret is ever needed — only the attacker's own organization's secret, which they are expected to possess. This makes the attack straightforward to mount for any tenant on a multi-org deployment.

### Recommendation
Bind the authenticated organization to the resource being acted upon: after `verify_webhook_signature` succeeds, re-derive `repository.owner.login` from the same payload used to compute `repository_name`/`full_name` in `Handler`, and assert they match (case-insensitively) before dispatching to any handler; reject (422) on mismatch. Alternatively, pass the already-verified `repository_owner` into `Handler.call`/`Handler#initialize` and have `Handler#stacks` scope its `Repository.from_github_repo_name` lookup to repositories whose `owner` equals the verified organization, rather than trusting `full_name` alone.

### Proof of Concept
1. Attacker controls organization `attacker-org`, configured on the shared Shipit instance with `webhook_secret = S`.
2. Attacker knows a victim stack tracks `victim-org/victim-repo` on the same instance.
3. Attacker builds a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` using their own known secret `S`.
5. POST to `/github/webhooks` (or the engine-mounted webhook endpoint) with `X-Github-Event: push`.
6. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GithubApp`, and successfully verifies the signature against `S` (`app/controllers/shipit/webhooks_controller.rb:24-30`).
7. `PushHandler#process` resolves `repository_name` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and enqueues `GithubSyncJob` for the victim's stack with the attacker-chosen `after` SHA (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`, `app/jobs/shipit/github_sync_job.rb:18-20`), all without ever touching `victim-org`'s credentials.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-20)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
```

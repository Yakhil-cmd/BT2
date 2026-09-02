### Title
Webhook signature verification is keyed on an attacker-controlled `repository.owner.login` field while the actual write target is selected from an equally attacker-controlled `repository.full_name` field, allowing unauthenticated writes against any configured repository — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is a direct analog of the reported bug class: a value used to compute/gate a critical decision (there: `wstETHToTransfer`, truncated to 0 by floor division and silently detached from the real share transfer) is derived from data that is not actually bound to the operation it authorizes. Here, the "authorization" (HMAC signature check) is bound to an `organization` value read out of the *same unverified JSON body* that later determines which repository/stack the webhook event is applied to, and those two payload fields are never checked for consistency.

### Finding Description
`Shipit::WebhooksController#verify_signature` derives the signing key to check against by reading the organization straight out of the untrusted request body, before the signature has been validated: [1](#0-0) [2](#0-1) 

`repository_owner` is computed from `params.dig('repository', 'owner', 'login')` — a field inside the JSON body the caller supplies. `Shipit.github(organization: repository_owner)` looks up the `GitHubApp` (and its `webhook_secret`) for that claimed organization: [3](#0-2) 

`GitHubApp#verify_webhook_signature` explicitly **bypasses verification entirely** when no `webhook_secret` is configured for that organization: [4](#0-3) 

Meanwhile, every event handler determines the actual repository/stack to act on from a *different* field of the same unverified body — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [5](#0-4) 

Because `repository.owner.login` (used to pick the signing key) and `repository.full_name` (used to pick the target stack) are two independent, unauthenticated fields in the same forged JSON, they are never required to agree. If **any** configured GitHub organization in the deployment has no `webhook_secret` set (the documented multi-org config schema explicitly allows per-organization secrets to be blank, and the example/dummy configs in this repo show `webhook_secret: # nil` for multiple orgs), an attacker can craft a payload where `repository.owner.login` names that unsecured organization (so `verify_webhook_signature` returns `true` unconditionally) while `repository.full_name` names a stack belonging to a fully-secured, unrelated organization/repository. The signature check passes trivially, but the handler that runs (`PushHandler`, `MembershipHandler`, `PullRequest::*Handler`, `StatusHandler`, `CheckSuiteHandler`, etc.) then dispatches real side effects against the victim stack: [6](#0-5) 

This is exactly the "equality that should hold but doesn't" pattern from the report: `organization_bound_by_the_verified_signature == organization_that_actually_owns_the_written_repository/stack` is assumed but never enforced, just as `wstETHToTransfer` was assumed to reflect the actual share transfer but was allowed to diverge from it.

### Impact Explanation
This lets an unprivileged network attacker who knows only (a) the name of one Shipit-configured organization that happens to have no `webhook_secret`, and (b) the `full_name` of a *different*, secured target repository, inject forged webhook events (`push`, `pull_request`, `status`, `check_suite`, `membership`) against that target's stacks without ever knowing the target's real webhook secret. Concretely reachable effects include: forcing `GithubSyncJob`/`sync_github` on a protected stack via a forged `push` event, forging `status`/`check_suite` results that feed `Commit#deployable?` and `MergeRequest::StatusChecker` (used to gate `allows_merges?`/`merge!`), and — most severe — forging `membership` events to add/remove `Membership` records and thereby escalate or de-escalate a user's standing in `Shipit.github_teams`, which is the exact "escalation into `Shipit.github_teams` authorization" High-impact category called out for this engine.

### Likelihood Explanation
Requires only: (1) network access to the `/webhooks` endpoint (unauthenticated by design, that's its purpose), (2) knowledge that some organization in the deployment's `secrets.yml` has a blank `webhook_secret` (plausible in the documented multi-org setup, since each org's `webhook_secret` is independently optional, and shown as `nil` in the repo's own example/dummy configs), and (3) the target's repository `full_name`, which is public knowledge for any GitHub repo. No credentials, GitHub App keys, or `ApiClient` tokens are needed — it is purely a body-crafting attack against the public webhook endpoint.

### Recommendation
Bind the signature verification to the same repository identity used for dispatch: require that `repository.owner.login` (or `organization.login`) match the owner parsed from `repository.full_name` before selecting a `GitHubApp`/secret, and reject the request if they diverge. Additionally, do not allow `verify_webhook_signature` to silently return `true` for organizations with a blank `webhook_secret`; instead, either require a `webhook_secret` for every configured organization or explicitly fail closed when one is missing, and validate the incoming payload against the specific `Repository`/`Stack`'s own configured secret rather than an organization-lookup performed on unverified data.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `openorg` (no `webhook_secret` set) and `secureorg` (a `webhook_secret` configured), each hosting one or more stacks, per the documented multi-org schema (`docs/setup.md` "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a body such as:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha, or a sha that already exists on secureorg/target-repo>",
  "repository": {
    "owner": { "login": "openorg" },
    "full_name": "secureorg/target-repo"
  }
}
```
Do not include a valid `X-Hub-Signature`, or include an arbitrary one.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "openorg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally per [7](#0-6) , and the request proceeds.
4. `Shipit::Webhooks::Handlers::PushHandler#process` resolves stacks via `Repository.from_github_repo_name("secureorg/target-repo")` (per [8](#0-7)  and [9](#0-8) ) and triggers `sync_github` against the secured stack — a write the attacker could not have produced through `secureorg`'s real, properly-secreted webhook without knowing its `webhook_secret`.

I was not able to further trace exact server-side effects of `MembershipHandler`/`StatusHandler`/`CheckSuiteHandler` within this session's remaining tool budget (their files were located but not read before the session ended), so the `Shipit.github_teams` escalation claim above is based on `Team`'s modeled relationship to `GithubHook::Organization`/`membership` events ( [10](#0-9) ) rather than a fully read-through trace of `membership_handler.rb`; a Devin session with full file access should verify that handler's exact write path before treating the `github_teams` escalation claim as conclusively proven.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
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

**File:** app/models/shipit/team.rb (L10-16)
```ruby
    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false

```

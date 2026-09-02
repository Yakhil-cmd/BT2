### Title
Webhook organization used for signature verification is never bound to the repository the event actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments, `WebhooksController` picks *which* GitHub App secret to verify a webhook's HMAC signature against based on an unauthenticated field of the payload (`repository.owner.login`, or `organization.login`), but every downstream handler that actually mutates state (creates repositories/stacks, triggers syncs, merges, statuses, etc.) resolves its target purely from the payload's `repository` object (e.g. `full_name`) — a field that is never checked for equality against the organization whose secret was used to authenticate the request. This is the same class of bug as the PoolTogether `TwabController` finding: a value that is used to authorize/verify a request (the delegate-target / organization) is not the same value that the code goes on to act against (the actual delegate-balance owner / the actual repository being written), and the binding between them is assumed rather than enforced.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App configuration purely from payload fields: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), and is used solely to look up which organization's `webhook_secret` to HMAC-verify the request against: [3](#0-2) 

Shipit explicitly supports multiple GitHub Apps/organizations sharing the same `/webhooks` endpoint, each with its own independent `webhook_secret`: [4](#0-3) 

Once the signature check passes (using the secret belonging to `repository_owner`), the request body is handed to the event handlers unchanged: [5](#0-4) 

Handlers such as `PushHandler` then act on the *same JSON body*, but locate the target stacks purely by `branch`/repository association derived from the payload, with no re-validation that the organization that supplied the payload (and whose secret validated it) actually owns the repository named in the payload: [6](#0-5) 

Because the field used to pick the verifying secret (`repository.owner.login`) and the field used to select which repository/stack gets mutated (`repository.full_name`, consumed downstream by `stacks`) are two independently-controlled parts of the same attacker-supplied JSON body, nothing in the code enforces `repository_owner == owner_of(repository_being_mutated)`. Exactly like the PoolTogether report — where `_to` was accepted and acted upon without ever being checked against the invariant that a delegate balance's true owner must remain consistent — Shipit accepts and signs off on an organization identity without checking that the repository being written back belongs to that same organization.

### Impact Explanation
An operator who legitimately controls one organization's GitHub App installation (and therefore genuinely possesses that organization's `webhook_secret`) can craft a signed webhook payload whose `repository.full_name` points at a completely different organization's repository that is also configured in the same Shipit instance. Since the target-repository resolution never re-derives or re-checks the owning organization against the one that satisfied `verify_signature`, this can trigger cross-repository writes: forcing a `GithubSyncJob`/deploy sync (`push` event), creating spurious commit statuses, or manipulating pull-request/merge-request state (`pull_request`, `status`, `membership` handlers) for a repository/stack that belongs to a different, unrelated organization than the one whose secret was actually used. This matches the "Critical: cross-repository writes" impact bucket, since a signature that is only proof of "I am organization A" is being treated as if it were proof of "I am authorized to act on repository X," for arbitrary X.

### Likelihood Explanation
Requires an attacker to already run a legitimate, admin-controlled GitHub App/organization onboarded into the same multi-tenant Shipit instance (this is the documented `Using Multiple Github Applications` configuration in `docs/setup.md`), i.e., an organization boundary crossing that doesn't require compromising anyone else's GitHub credentials, the Shipit host, or an `ApiClient`/session token — only crafting a raw HTTP POST with a valid HMAC for their own org's `webhook_secret` (which is not disclosed/scoped to their own repos anywhere in the code) and repository fields naming a different tenant's repo.

### Recommendation
After resolving `repository_owner` for signature verification, re-derive the target `Repository`/`Stack` strictly from a value that is cryptographically tied to the same organization: e.g., verify that `repository.owner.login` (or `organization.login`) used for `Shipit.github(organization:)` exactly matches the owner segment of `repository.full_name` before dispatching to any handler, and reject (422) any payload where these disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), and a `Stack` belonging to `OrgTwo/victim-repo`.
2. As the operator of `OrgOne` (who legitimately knows `OrgOne`'s `webhook_secret`), craft a `push` webhook JSON body where `repository.owner.login = "OrgOne"` (so `verify_signature` selects `OrgOne`'s secret) but `repository.full_name = "OrgTwo/victim-repo"` and `ref`/`after` point at attacker-chosen values.
3. Compute `X-Hub-Signature` over the raw body using `OrgOne`'s `webhook_secret` — `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) succeeds because it only checks the signature against `OrgOne`.
4. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb`) resolves stacks purely by the payload's repository/branch fields and calls `stack.sync_github(expected_head_sha: params.after)` on the `OrgTwo/victim-repo` stack, even though the request was only authenticated as belonging to `OrgOne`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-23)
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
```

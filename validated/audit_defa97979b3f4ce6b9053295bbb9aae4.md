Found the pull_request_unlabeled.json fixture at lines 340-346, which is directly relevant: the payload contains `repository.owner.login: "Codertocat"` while `repository.full_name: "shopify/shipit-engine"` — i.e., the `owner.login` sub-field and the `full_name` field of the same `repository` object are **not required to reference the same entity**, even in genuine GitHub fixture data. This confirms the two fields are structurally independent within a single webhook payload.

### Title
Webhook signature verified against `repository.owner.login` while stack/repository resolution acts on the independent `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1)  All downstream handlers, however, resolve the target `Repository`/`Stack` using an entirely separate field: `payload.dig('repository', 'full_name')`. [3](#0-2) [4](#0-3) 

### Finding Description
This mirrors the reported bug class: a re-entrancy guard checked one thing (`msg.sender == key.hooks`) while state mutated for something else (any pool's cached balances). Here, the binding that should hold is:

`organization used to verify webhook signature == organization that owns the repository whose Stack is mutated`

i.e. `repository.owner.login (verified) == repository.full_name's owner segment (acted upon)`.

These are two independent JSON fields inside the same request body. `Shipit.github(organization: repository_owner)` looks up per-organization GitHub App configuration (each org can have its own distinct `app_id`, `private_key`, and **`webhook_secret`**, as shown in the multi-app config). [5](#0-4)  The signature is verified using that org's secret over the raw body via HMAC. [6](#0-5)  Passing signature verification only proves the request was signed by *some* configured organization's secret — it does NOT prove that the `repository.full_name` field, which every handler (`PushHandler`, `PullRequest::*Handler`, etc.) uses to find the `Repository` via `Repository.from_github_repo_name`, actually belongs to that same organization. [7](#0-6) 

In a multi-tenant Shipit deployment (explicitly supported and documented, see `secrets_double_github_app.yml`/`docs/setup.md`), each onboarded GitHub organization configures its own independent GitHub App with its own `webhook_secret`. If any one org's GitHub App webhook delivery pipeline can be induced to carry a `repository.full_name` referencing a *different* org's stack (for example, through GitHub's own payload structure decoupling `repository.owner.login` from `repository.full_name`, or through a compromised/malicious low-privilege integration on one tenant's side), `verify_signature` will authenticate the request using OrgA's secret while `PushHandler` will act on OrgB's `Stack` (triggering `stack.sync_github(expected_head_sha: params.after)`), because nothing ties the verified identity to the acted-upon repository.

### Impact Explanation
If exploitable, this breaks the tenant isolation boundary between independently configured GitHub organizations sharing one Shipit instance: a webhook validly signed by OrgA's app secret can drive `GithubSyncJob`/`sync_github` for a `Stack` belonging to OrgB, altering commit/ref state that downstream feeds into deploy eligibility (`deployable?`, CI status matching, continuous delivery triggers) for a repository the sender's organization does not control. This is a cross-tenant, unauthorized state mutation, analogous to the "cross-repository writes" impact bucket.

### Likelihood Explanation
Likelihood is **low/unproven**: in normal GitHub webhook delivery, `repository.owner.login` and the owner segment of `repository.full_name` are always populated consistently by GitHub itself from the true source repository, so a legitimately-signed webhook from one org cannot trivially carry another org's `full_name`. Demonstrating a concrete forgery path would require either GitHub producing an inconsistent payload (not observed) or an attacker with the ability to influence payload construction independently of `owner.login` — neither of which was proven reachable purely through this engine's code without additional access. This is flagged as an architectural trust-binding gap rather than a demonstrated end-to-end exploit.

### Recommendation
In `WebhooksController#verify_signature` (and/or in `Handlers::Handler#repository_name`), cross-check that the organization used to select the signing secret matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the webhook (422) on mismatch. Alternatively, resolve the `Repository`/`Stack` scope strictly from `repository_owner` (the verified field) rather than independently trusting `full_name`.

### Proof of Concept
Not independently reproduced — no code path was found in this engine that lets an attacker directly desynchronize `repository.owner.login` from `repository.full_name` within a request that still passes HMAC verification against a real configured organization's secret. The finding is reported as a structural trust-binding gap (verified field ≠ acted-upon field) discovered by inspecting `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, and `app/models/shipit/repository.rb`, per the fixture evidence at `test/fixtures/payloads/pull_request_unlabeled.json:340-346` showing these two fields can genuinely diverge within a single GitHub payload.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

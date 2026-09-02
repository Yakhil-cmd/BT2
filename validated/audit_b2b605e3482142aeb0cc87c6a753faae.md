### Title
Webhook signature verification is bound to `repository.owner.login`, but stack-mutating handlers act on the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization config — and therefore the `webhook_secret` used for HMAC verification — using `repository_owner`, which is read directly from the untrusted JSON body before any signature check occurs. Once the signature is confirmed for *that* organization, the full, still-attacker-supplied payload (including a `repository.full_name` field that need not match `repository.owner.login`) is handed to the event handlers, which use `repository.full_name` (not `repository.owner.login`) to look up the target `Stack`/`Repository` and perform state-changing actions.

### Finding Description
`verify_signature` computes the org used for verification like this: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` resolves a per-organization `GitHubApp` (with its own `webhook_secret`) from `secrets.github`, supporting multi-organization deployments: [3](#0-2) 

`verify_webhook_signature` only proves that the *entire raw body* was HMAC-signed with the secret belonging to whichever organization `repository_owner` names — it does not constrain any other field inside that body to belong to that same organization: [4](#0-3) 

After verification passes, the full payload is dispatched to handlers unmodified: [5](#0-4) 

Every state-mutating handler, however, resolves the target repository/stack from `repository.full_name`, not from `repository.owner.login`: [6](#0-5) [7](#0-6) [8](#0-7) 

This is precisely the same class of bug as the LinkedList sentinel report: the sentinel/verification is anchored to one identity (`repository.owner.login`, the "sentinel"), while the action actually performed is driven by a second, independent field (`repository.full_name`) that the verification never constrained to agree with the first. The binding that should hold — "the organization whose secret authenticated this request" == "the repository/organization whose stack is mutated" — is broken.

Concretely, in a multi-organization Shipit deployment (the schema `TOP_LEVEL_GH_KEYS`/`github_app_config` exists specifically to support several orgs sharing one Shipit instance), the holder of Organization A's `webhook_secret` (e.g., an org owner who configured that org's GitHub webhook against this Shipit instance) can POST directly to the public `/github/webhooks` endpoint with:
- `repository.owner.login = "org-a"` (so `Shipit.github(organization: "org-a")` is selected and the HMAC computed with `org-a`'s secret validates), and
- `repository.full_name = "org-b/victim-repo"` (or `organization.login` swapped similarly for the `membership` handler), pointing at a stack/repository that belongs to a different, unrelated organization.

Because `Handler#stacks`/`#repository_name` only look at `repository.full_name`, the handler will locate and act on Organization B's stack even though the signature never covered Organization B's secret.

### Impact Explanation
This breaks the deployment-trust binding between "the organization that authenticated the webhook" and "the repository that is written to," matching the Critical bucket ("cross-repository writes"/"unauthorized deploy"): a `push` event forged this way calls `stack.sync_github(expected_head_sha:)` on a stack belonging to a foreign organization, which enqueues `GithubSyncJob`, ingests attacker-influenced commit data via the stack's own `github_api`, and can trigger `CacheDeploySpecJob`. Similarly the `pull_request` handlers (`OpenedHandler`, `LabeledHandler`, etc.) will archive/unarchive or provision review stacks belonging to the victim organization, and `MembershipHandler` can add/remove team membership records, driven entirely by an org whose secret the attacker legitimately possesses but which does not own the target repository.

### Likelihood Explanation
Exploitation requires: (1) the Shipit instance to be configured for multiple organizations (`secrets.github` keyed by org) so that more than one distinct `webhook_secret` exists, and (2) the attacker to control/know one organization's `webhook_secret` (e.g., as the admin who set up that org's webhook pointing at the shared Shipit instance) while wanting to affect a different organization's stacks. This is a realistic scenario for shared/hosted Shipit deployments serving multiple GitHub orgs, but not exploitable against a single-organization deployment (where `repository_owner` always resolves to the one configured org). Likelihood is therefore Medium — it needs a specific but plausible multi-tenant configuration and possession of one org's legitimate webhook secret.

### Recommendation
- After verifying the signature for the organization derived from `repository_owner`, re-validate that every organization-identifying field used later by handlers (`repository.full_name`'s owner segment, `organization.login`, etc.) is consistent with `repository_owner` before dispatching to handlers, and reject the request (422) otherwise.
- Alternatively, bind handler repository/stack lookups to the same verified organization identity used for signature verification instead of trusting `repository.full_name` independently.
- Add a regression test asserting that a payload signed by Org A's secret but referencing Org B's `repository.full_name` is rejected.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `org-a` and `org-b`, each with its own `webhook_secret`.
2. As the party who controls `org-a`'s webhook secret (e.g., an org-a admin who configured the webhook), craft a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a webhook_secret, raw_body)>` and POST to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and validates the HMAC successfully.
5. `Shipit::Webhooks.for_event('push')` runs `Handlers::PushHandler`, which resolves stacks via `Repository.from_github_repo_name("org-b/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on Organization B's stack — an action never authorized by Organization B's secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

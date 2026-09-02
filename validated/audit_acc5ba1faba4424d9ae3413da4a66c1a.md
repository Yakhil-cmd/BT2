### Title
Webhook signature is verified against an attacker-chosen organization while the acted-upon repository comes from an unvalidated payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read directly from the untrusted JSON body (`repository.owner.login` or `organization.login`). Every webhook handler, however, resolves the repository/stack that is actually mutated using a *different* field of the same untrusted body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so a signature that is valid for organization A does not guarantee the payload's target repository actually belongs to organization A.

### Finding Description
`verify_signature` computes the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves a distinct `GitHubApp` instance, each with its own independently configured `webhook_secret`, when the engine is configured for multiple GitHub organizations: [3](#0-2) 

The HMAC check itself only proves the request was signed with *some organization's* secret, chosen by the attacker-controlled `repository_owner` value: [4](#0-3) 

But every event handler (`PushHandler`, PR handlers, etc.) determines the actual repository/stack to mutate from a *separate* field, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name` / `#stacks`, with no cross-check that this repository belongs to the organization whose secret validated the request: [5](#0-4) [6](#0-5) 

This is structurally the same bug class as the reported JIT/interpreter divergence: two code paths are supposed to agree on a single logical value (“which organization is this webhook for”), but one path derives it from an unverified field (`repository.full_name`) while the other derives it from a different unverified field (`repository.owner.login` / `organization.login`) that is coincidentally covered by the signature check. The equality the code implicitly assumes — `organization that signed the request == organization owning the repository being written to` — is never enforced.

### Impact Explanation
Any party who knows (or can compute) the `webhook_secret` for **any one** organization configured on a multi-org Shipit instance (e.g., the owner of a small/low-trust organization that was legitimately onboarded onto the same Shipit deployment) can forge a webhook POST directly to `/webhooks`:
- Set `X-Hub-Signature` = HMAC-SHA1 computed with their own organization's `webhook_secret`.
- Set `repository.owner.login` (or `organization.login`) to their own organization, so `verify_signature` looks up and validates against their own secret.
- Set `repository.full_name` to an arbitrary **other** organization/repository tracked by the same Shipit instance.

The resulting payload passes signature verification, and the handler acts on the attacker-chosen repository. For `push` events this triggers `stack.sync_github(expected_head_sha: ...)` on the victim's stacks (`PushHandler#process`), which can drive continuous-delivery/undeployed-commit state for a stack the attacker does not control; other handlers (`status`, `check_suite`, `pull_request` family) similarly let the attacker manipulate commit statuses, review-stack archive/unarchive state, and merge status for repositories/organizations they have no relationship to. This crosses the "cross-repository writes" impact bar defined by the rules, since one organization's credential is used to write state belonging to a different organization/repository.

### Likelihood Explanation
Exploitation requires only knowledge of a `webhook_secret` for *any* organization onboarded to the shared Shipit instance — not the target organization's secret, GitHub App private key, a Shipit session, or an `ApiClient` token. In any deployment where Shipit is shared across multiple organizations/teams (the multi-org config path explicitly supported by `Shipit.github_organizations`/`github_app_config`), a lower-trust tenant can pivot into higher-trust tenants' repositories purely by sending a crafted, self-signed HTTP request — no interaction with the real GitHub webhook delivery pipeline is required.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), require that the organization/owner used to select the verifying secret matches the owner of `repository.full_name` used by the handler, e.g., derive both from the same normalized value and reject the request if `repository.owner.login` does not match the owner segment of `repository.full_name`. Alternatively, bind webhook secrets to the specific repository (not just the organization) so that signature validity is inherently scoped to the exact repository being acted upon.

### Proof of Concept
Given a multi-org Shipit config with organizations `orgA` (attacker-controlled, secret known) and `orgB` (victim, repo `orgB/victim-repo` tracked by Shipit):
1. Build a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
2. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>`.
3. `POST /webhooks` with header `X-Github-Event: push` and the above body/signature.
4. `verify_signature` resolves `Shipit.github(organization: "orgA")` and successfully verifies the signature using `orgA`'s secret.
5. `PushHandler` resolves the target via `payload.dig('repository','full_name') == "orgB/victim-repo"`, and calls `stack.sync_github(...)` on `orgB`'s stacks — despite the request never having been authenticated by `orgB`.

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

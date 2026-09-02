### Title
Webhook organization/signature check is decoupled from the repository whose data gets written, allowing unauthenticated forgery of commit statuses - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config to use for HMAC verification based on attacker-controlled JSON fields (`repository.owner.login` / `organization.login`), while the handlers that actually mutate state (in particular `StatusHandler`) never check that the incoming event's organization matches the record being written. Combined with the documented, optional `webhook_secret` (which causes signature verification to be skipped entirely when absent), an unprivileged sender can post a webhook that is "authenticated" against one (unsecured) tenant configuration while writing data belonging to an entirely different repository/stack.

### Finding Description
`verify_signature` resolves the org to check the signature against purely from the payload: [1](#0-0) 

That org selection feeds into `Shipit.github(organization: repository_owner)`, whose `verify_webhook_signature` short-circuits to `true` whenever the resolved app config has no `webhook_secret` configured, regardless of the actual `X-Hub-Signature` header value: [2](#0-1) 

Multi-tenant configurations look up per-organization app configs by name, and `webhook_secret` is documented as optional per app, so it is realistic for one configured organization to have no secret while others do: [3](#0-2) 

Once past `verify_signature`, the dispatched handler acts on data derived from the same JSON body, but the two most sensitive handlers apply the binding inconsistently. `Handler#repository_name`/`#stacks` scope events to a repository via `payload.dig('repository', 'full_name')`: [4](#0-3) 

But `StatusHandler#process` does not use that repository scoping at all — it looks up `Commit` records globally by `sha` across the entire installation, with no relation to the organization that "authenticated" the webhook nor to which repository the commit belongs: [5](#0-4) 

This breaks the binding "organization that authenticated the webhook == repository/commit whose data is written": the signature check only proves the sender knows (or does not need) the secret of some configured tenant, yet the mutation (`Commit#create_status_from_github!`) can target any commit in the whole Shipit instance, including commits belonging to stacks configured under a different, properly-secured organization.

### Impact Explanation
Commit statuses are used by Shipit to gate deploys via deployable/commit status checks (`Commit#create_status_from_github!`, surfaced as `deployable_status`). An attacker who can post a forged `status` event for any known commit `sha` (SHAs are public GitHub metadata, not secrets) can inject a fabricated "success" status for a commit belonging to a repository they have no access to, potentially clearing a deploy-blocking check and enabling an unauthorized deploy — this matches the Critical "unauthorized deploy" impact category. No `webhook_secret`, `ApiClient` token, GitHub App private key, or Shipit session is required — only knowledge that one configured tenant in a multi-org install omits `webhook_secret` (an explicitly supported/optional configuration), and the target commit's SHA.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment (multiple orgs under `secrets.github`), and (2) at least one configured organization without a `webhook_secret` set — both of which are supported, documented configurations rather than misuse of the engine. Given those preconditions, exploitation needs no privileged credential at all — it is a plain unauthenticated HTTP POST to `/webhooks` with a JSON body naming the unsecured org as `repository.owner.login`/`organization.login` and a target `sha` belonging to a different repository.

### Recommendation
- Scope every webhook handler (especially `StatusHandler`) to the repository resolved for signature verification (`repository_owner`), not just to the `sha`/`full_name` embedded in the same untrusted payload.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in multi-tenant configurations; require an explicit non-secret opt-in, and reject webhooks whose declared `repository.owner.login` doesn't match the repository actually being mutated.
- Cross-check that the organization used to select the signing secret is the same organization that owns the repository referenced by `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations under `secrets.github`: `secure-org` (with `webhook_secret` set) and `test-org` (with no `webhook_secret`), consistent with the documented "optional" secret setup.
2. Track a stack for `secure-org/victim-repo` with a pending/blocking deployable status check on commit `abc123`.
3. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "abc123",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "test-org" }, "full_name": "test-org/unrelated-repo" }
}
```
4. `repository_owner` resolves to `test-org`; `Shipit.github(organization: "test-org").verify_webhook_signature` returns `true` unconditionally because `test-org` has no `webhook_secret` — no valid `X-Hub-Signature` is needed.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, finds the commit under `secure-org/victim-repo`, and calls `create_status_from_github!`, marking the check as `success` — even though the request was never signed by `secure-org` and never referenced `victim-repo`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

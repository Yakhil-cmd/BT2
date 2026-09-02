### Title
Cross-tenant webhook forgery via organization/repository binding mismatch in `WebhooksController` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-tenant Shipit deployments, the field used to select which GitHub App secret authenticates a webhook (`repository.owner.login` / `organization.login`) is never verified to match the field the webhook handlers actually act on (`repository.full_name`). A tenant that legitimately controls one onboarded GitHub organization's webhook secret can forge events that are authenticated as "their" org but target any other tenant's repository, driving privileged side effects (fake commit statuses, forced stack syncs, review-stack archival) on stacks they do not own.

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to validate against using `repository_owner`, computed straight from the unverified JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct config (and `webhook_secret`) per organization key in `secrets.github` when running in multi-org mode: [3](#0-2) 

`GitHubApp#verify_webhook_signature` even treats a blank `webhook_secret` as automatically verified: [4](#0-3) 

Once the signature step passes, every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`, etc.) resolves the actual `Repository`/`Stack` to mutate from an *entirely different* payload field — `payload.dig('repository', 'full_name')` — with no cross-check against the organization that was authenticated: [5](#0-4) [6](#0-5) [7](#0-6) 

The broken binding, expressed as an equality that the engine never enforces:
`organization authenticated via verify_signature (repository.owner.login / organization.login)` **should equal** `organization implied by repository.full_name that the handler writes to`.

Because both fields are attacker-controlled JSON body content and only the first is covered by the HMAC signature computation (`OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message)` is computed over the *whole* raw body, but the secret chosen to compute it depends only on `repository_owner`), a caller who legitimately possesses (or simply lacks, when unset) the webhook secret for organization A can sign a payload where `repository.owner.login` = "A" (to pick A's secret) while `repository.full_name` = "B/victim-repo" (to target organization B's stack).

### Impact Explanation
This breaks the deployment-trust binding between "who authenticated" and "what gets written," letting a webhook authenticated for tenant A act on tenant B's stacks:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack, forcing a resync of HEAD/commits used by the deploy pipeline.
- `StatusHandler#process` calls `commit.create_status_from_github!` for any commit sha across the whole install (not scoped by repo at all), letting a cross-tenant caller inject/forge CI status for arbitrary commits, which can influence deploy-gating checks and lead to an unauthorized deploy.
- `PullRequest::*Handler`s can archive/unarchive review stacks or mutate labels of victim repositories.

This maps to the Critical bucket in the given scope ("cross-repository writes" / "an unauthorized deploy") because it lets an actor authenticated for one repository/organization mutate state belonging to another repository/organization it has no relationship with.

### Likelihood Explanation
Requires only a multi-organization Shipit deployment (supported and documented via `Shipit.github_organizations`/`github_app_config`) where the attacker is one of the onboarded, non-privileged tenants (or any org whose config lacks a `webhook_secret`, which auto-passes verification). No repository write access, no `ApiClient` token, and no privileged Shipit account are required — only the ability to send an HTTP POST to the public `/github/webhooks` endpoint with a body they can sign using credentials for their own tenant (or no credentials at all if that tenant's `webhook_secret` is unset).

### Recommendation
After verifying the signature, re-derive the organization from the same field used for signature selection and require it to equal the owner of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers; reject the request otherwise. Do not allow a blank `webhook_secret` to implicitly verify — require an explicit opt-out. Additionally, scope `StatusHandler`'s `Commit.where(sha: params.sha)` lookup to commits belonging to the repository asserted in the (now-validated) payload, not globally.

### Proof of Concept
1. Configure Shipit multi-tenant with two organizations in `secrets.github`: `orgA` (attacker-controlled, known `webhook_secret`) and `orgB` (victim, has a tracked `Repository`/`Stack`).
2. Compute `sha1=HMAC(orgA_webhook_secret, raw_body)` for a payload:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>"
}
```
3. POST to `/github/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` computes `repository_owner = "orgA"`, fetches orgA's secret, and the signature validates successfully.
5. `PushHandler#process` uses `repository.full_name = "orgB/victim-repo"` to look up `orgB`'s stacks and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")`, an action orgA has no authorization to trigger on `orgB`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

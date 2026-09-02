### Title
Webhook signature verification keyed on unverified `repository.owner.login`/`organization.login` while handlers act on the unverified `repository.full_name` - allows cross-organization stack manipulation (`app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to check the HMAC signature against by reading an **unverified** field from the still-unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, `Shipit::Webhooks::Handlers::Handler#repository_name` — used by every event handler (push, pull_request, status, etc.) to locate the target `Stack`/`Repository` — reads a **different** field of that same unverified body: `repository.full_name` [1](#0-0) . Nothing ties these two fields together, so a signature that is valid for organization A's webhook secret can be used to act on a Shipit `Stack` belonging to a repository under organization B, as long as both A and B are configured in the same Shipit instance.

### Finding Description
`verify_signature` computes the org used for signature verification purely from the payload:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

That value picks the `GitHubApp` (and hence the `webhook_secret`) used to verify `X-Hub-Signature` via `Shipit.github(organization: repository_owner).verify_webhook_signature`. Since Shipit explicitly supports multiple GitHub organizations, each with its own `webhook_secret` in `secrets.github[org]`, this becomes an organization-scoped credential lookup: [3](#0-2) .

Once the request passes this check, `WebhooksController#create` dispatches the *entire raw payload* to the registered handler(s) for the event:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

All handlers derive the target repository/stack from a *different* JSON field:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`PushHandler` uses exactly this to select stacks and trigger a `GithubSyncJob`:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

`repository.owner.login` (used for the signature key) and `repository.full_name` (used for the target stack) are **never cross-checked**. The signature only proves "this payload was HMAC-signed with organization A's `webhook_secret`" — it says nothing about which repository the payload claims to describe. `Repository.from_github_repo_name` splits `owner/name` straight from the attacker-controlled `full_name` string with no relation to the org that produced a valid signature: [6](#0-5) .

**Binding broken (as an equality):**
`organization authenticated by verify_signature (repository.owner.login / organization.login)` ≠ `repository written/acted upon by the handler (repository.full_name)`.

Before the fix implied by this analog, these two fields are implicitly assumed equal by the controller design; there is no code enforcing that assumption. After an attacker-controlled request, the two diverge: the signature verifies against org A's secret while the handler operates on org B's `Stack`.

### Impact Explanation
This is a self-service (multi-tenant) Shipit deployment scenario, explicitly documented as supported ("Using Multiple GitHub Applications", `docs/setup.md`). An attacker who legitimately owns/administers organization A (and therefore knows or can obtain A's `webhook_secret`, e.g., because they configured the GitHub App/webhook for their own org) can:

- Craft an HTTP POST directly to `/webhooks` (bypassing GitHub) with `X-Github-Event: push`, a body where `repository.owner.login` = "org-a" (their own org, so signature verification succeeds against org-a's known secret) but `repository.full_name` = "org-b/victim-repo" (a repository belonging to a different tenant configured in the same Shipit instance).
- Sign the raw body with org-a's `webhook_secret` per `GitHubApp#verify_webhook_signature` [7](#0-6) .
- Since verification succeeds, `PushHandler` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and enqueues `GithubSyncJob` for any of org-b's non-archived stacks matching the attacker-chosen branch, with an attacker-chosen `expected_head_sha` [8](#0-7) .

This forces org-b's stack to sync toward a specific commit not caused by any real push to org-b's repository, which can trigger unwanted deploy pipelines (continuous deployment stacks auto-deploy on new commits), cause stacks to be marked inaccessible/accessible, or otherwise manipulate deployment state for a repository the attacker does not control — an unauthorized cross-tenant action on Shipit's deploy state. This matches the "High" bucket: escalation across a repository/organization trust boundary that the signature was supposed to enforce, without requiring possession of org-b's own webhook secret, `ApiClient` token, or GitHub repo write access.

### Likelihood Explanation
Likelihood is meaningful only in genuinely multi-tenant Shipit deployments where multiple organizations' secrets are configured side by side (a documented, supported configuration). The attacker needs no privileged access to the victim org or repo — only the ability to know/derive a webhook secret for *any one* org configured on the instance (which they may legitimately have, e.g. because they administer their own org's GitHub App integration to that Shipit instance) and knowledge of the target `owner/name` and branch, both public/discoverable information. No GitHub session, `ApiClient` token, or TLS interception is required — a direct unauthenticated POST to `/webhooks` suffices as long as the signature is valid for *some* configured org.

### Recommendation
- In `WebhooksController#verify_signature`, after successfully verifying the signature for `repository_owner`, additionally require that every repository/organization field referenced further downstream (`repository.full_name`'s owner segment) matches the same `repository_owner`/organization used for verification, rejecting the payload (422) on mismatch.
- More robustly, have `Shipit::Webhooks::Handlers::Handler#stacks`/`repository_name` receive the already-authenticated organization from the controller and scope `Repository.from_github_repo_name` lookups to that organization, rather than trusting the unauthenticated `full_name` field's owner segment in isolation.
- Add coverage (mirroring `test/controllers/webhooks_controller_test.rb`) asserting that a payload signed with org A's secret but pointing to org B's repository is rejected.

### Proof of Concept
Given a Shipit instance configured with two organizations, `org-a` (attacker-controlled, secret known) and `org-b` (victim, has a stack `victim-repo`, branch `master`), from `config/secrets.yml`-style config as in `docs/setup.md`:

```
production:
  github:
    org-a:
      webhook_secret: known-secret-a
      ...
    org-b:
      webhook_secret: unknown-secret-b
      ...
```

1. Build payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-existing-in-org-b/victim-repo>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
2. Compute `X-Hub-Signature: sha1=<hmac-sha1(known-secret-a, raw_body)>`.
3. `POST /webhooks` with header `X-Github-Event: push` and the signature above.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-a")` (from `repository.owner.login`), and the signature validates successfully because it was in fact signed with `org-a`'s secret [9](#0-8) .
5. `PushHandler#stacks` resolves via `payload.dig('repository', 'full_name')` = `"org-b/victim-repo"`, unrelated to `org-a`, and enqueues `GithubSyncJob` for `org-b`'s stack with the attacker-supplied `expected_head_sha` [10](#0-9) .

This confirms the sync/deploy trigger fires for a stack in an organization the attacker does not control, using a signature that never authenticated anything about that organization or repository.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```

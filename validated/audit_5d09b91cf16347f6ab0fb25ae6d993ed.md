## Title
Cross-tenant webhook forgery — signature verified against the payload's `repository.owner.login`, but write is dispatched to the repository named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to check the inbound webhook against using a field taken directly from the *unauthenticated* JSON body (`repository.owner.login` / `organization.login`), while the handlers that actually mutate state (`PushHandler`, `StatusHandler`, etc.) resolve the target `Stack`/`Repository` using a different field of the same body, `repository.full_name`. Nothing binds these two fields together. In a multi-tenant Shipit install (multiple GitHub orgs configured under `github:`), anyone holding a valid webhook secret for their own onboarded organization can craft an arbitrary JSON body — since the endpoint is public and unauthenticated apart from HMAC — set `repository.owner.login` to their own org (so the signature check passes with their own secret) and set `repository.full_name` to any other tenant's `owner/repo`, driving writes against a repository they have no relationship to.

### Finding Description
`verify_signature` computes the org used for secret lookup purely from the payload, before any cryptographic check: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks the secret up per-organization from `secrets.github`, confirming this is a genuine multi-tenant configuration where each organization has its own independent `webhook_secret`: [3](#0-2) 

Once `verify_webhook_signature` succeeds (which only proves the raw body was HMAC-signed with *whatever secret corresponds to the org name embedded in the same body*), the event is dispatched to handlers. Every handler resolves its target stacks from a completely different field, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

`PushHandler` uses that repository lookup to enqueue `GithubSyncJob` for matching stacks/branches: [5](#0-4) 

`StatusHandler` uses `params.sha` (also attacker-controlled, unrelated to the org check) to attach a fabricated GitHub status directly to any `Commit` row matching that SHA, regardless of which repository/org it actually belongs to: [6](#0-5) 

Creating that status calls `Commit#create_status_from_github!` → `add_status`, which can trigger continuous delivery and merges: [7](#0-6) [8](#0-7) 

This is the exact class of bug in the report: a field that is checked/authenticated (`repository.owner.login`, used to pick the secret) is different from the field that is actually acted upon (`repository.full_name` / commit `sha`, used to pick the write target), and the binding between them is never enforced.

### Impact Explanation
An attacker who legitimately possesses the webhook secret for *one* onboarded organization in a shared/multi-tenant Shipit instance can forge webhook events attributed to any *other* onboarded organization's repositories:
- Force `GithubSyncJob` runs and status/commit writes against a victim stack they have no access to (cross-repository writes).
- Inject fabricated `success` CI statuses onto a victim commit, which can trigger continuous delivery (`Commit#add_status` → `stack.schedule_merges` / `commit.schedule_continuous_delivery`) and drive an unauthorized deploy on a repository the attacker does not own or administer.

This satisfies the Critical bar of "cross-repository writes" / "an unauthorized deploy" defined in scope, since it is a genuine binding break between the authenticated identity (`repository.owner.login`'s org secret) and the entity acted upon (`repository.full_name` / commit `sha`).

### Likelihood Explanation
Requires only possession of a webhook secret for any one org configured in the Shipit instance (not a Shipit session, `ApiClient` token, or privileged account) and the ability to POST directly to the public `/github_webhook` endpoint — no GitHub round-trip is required since Shipit never validates the request actually originated from GitHub, only that the body was HMAC-signed with the secret matching the org name embedded in that same body. This is realistic for any Shipit deployment onboarding more than one GitHub organization/tenant with distinct webhook secrets.

### Recommendation
Bind the authenticated identity to the object being written:
- After signature verification succeeds for organization `O`, enforce that every repository referenced in the payload (`repository.full_name`, and any `organization.login`) actually belongs to `O` before dispatching to handlers, rejecting the event otherwise.
- Alternatively, resolve the target `Repository`/`Stack` first, look up its owning organization from Shipit's own repository/stack records, and verify the signature using *that* organization's secret rather than trusting the org name asserted in the payload.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` under `secrets.github`.
2. As an attacker who administers `orgA` (and thus knows `orgA`'s `webhook_secret`, e.g. because they configured GitHub's webhook UI for their own org), build a JSON body:
```json
{
  "sha": "<victim-commit-sha-in-orgB>",
  "state": "success",
  "context": "ci/fake",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature` as `sha1=<HMAC-SHA1(orgA_webhook_secret, body)>`.
4. POST to `/github_webhook` with header `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` to `"orgA"`, fetches `orgA`'s secret, and the signature validates successfully.
6. `StatusHandler#process` matches `Commit.where(sha: params.sha)` — the victim commit under `orgB` — and calls `create_status_from_github!`, injecting a fabricated `success` status that can trigger continuous delivery/merge on `orgB`'s stack, without the attacker ever possessing `orgB`'s secret or any Shipit session for `orgB`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

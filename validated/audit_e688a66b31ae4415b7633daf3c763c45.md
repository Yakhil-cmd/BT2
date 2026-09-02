## Finding: `StatusHandler` binds a commit-status update to a raw commit SHA with no repository/organization scoping — breaking "organization authenticated == repository written"

### Title
Cross-Repository / Cross-Organization Commit Status Injection via `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook handler updates commit statuses for **any** `Shipit::Commit` row matching the SHA in the payload, regardless of which GitHub organization/repository the request was verified against. Because commit SHAs are globally unique-looking but not scoped to the signing organization inside the handler, a legitimate, correctly-signed webhook from **Org A** (whose secret is used to pass `verify_signature`) can flip the CI/deploy-readiness status of a commit that actually belongs to a stack owned by **Org B**, as long as the two share (or an attacker can predict/collide) a commit SHA reachable in Org B's stack history (e.g. via a forked/mirrored repository, a cherry-picked commit, or a rebase that preserves SHAs across repos the Shipit instance tracks).

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify against using data taken straight from the unverified/just-parsed JSON body: [1](#0-0) [2](#0-1) 

This design is intentional for Shipit's multi-organization support, where each organization has its own `webhook_secret` in `secrets.yml`: [3](#0-2) 

Once the signature check passes (i.e. the request truly came from GitHub for the organization named in `repository.owner.login`), the payload is dispatched to a handler purely by event type — the handler itself does **not** re-verify that the object it is about to mutate (`Commit`) actually belongs to the same organization/repository the signature was verified for: [4](#0-3) 

`process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped lookup across **every stack Shipit knows about**, not filtered by `repository_name`/`stacks` (contrast with `PushHandler`, which correctly scopes via `stacks.not_archived.where(branch:)`): [5](#0-4) [6](#0-5) 

`create_status_from_github!` writes a new `Status` and, critically, can trigger downstream trust-sensitive effects: enabling CI on the stack, and — depending on state transitions — scheduling continuous deployment/merges: [7](#0-6) [8](#0-7) [9](#0-8) 

**The equality that should hold but doesn't:** *organization whose webhook secret authenticated the request == organization owning the repository/commit being written to.* `verify_signature` binds the signature to `repository_owner` (org A), but `StatusHandler#process` binds the mutation to `sha` alone, with no re-check that the commit's `stack.repository`'s owning organization matches the one that signed the request. Any Shipit instance configured with more than one GitHub organization (as the engine explicitly supports and documents) is exposed: a webhook correctly signed for Org A's app can flip the `success`/`failure` state of a commit tracked under Org B's stack if the SHA happens to be shared or guessable (e.g., mirrored repos, forks, or a low-entropy short SHA collision across many tracked stacks), because the org-level signature is never carried through to the per-commit authorization check.

### Impact Explanation
Commit status directly gates safety mechanisms: it feeds `deployable?` (via CI-required statuses) and continuous-deployment triggers (`schedule_merges`, `ProcessMergeRequestsJob`) in other organizations' stacks. An attacker in control of one (less-trusted, correctly configured) organization onboarded to the same Shipit instance can, without any Shipit session or `ApiClient` token, force a fabricated `success` status onto a commit belonging to a different organization's stack, potentially unlocking `deployable?` gating and triggering an unauthorized deploy/merge in that other repository — meeting the "unauthorized deploy" bar. This is a cross-repository/cross-organization write achieved purely with a legitimately signed webhook for one's own org, i.e. no privileged credential for the victim org is required.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with multiple GitHub organizations (documented, supported feature), and (2) a SHA collision/overlap between a commit the attacker's org can push/trigger a `status` event for and a commit tracked in a victim stack (realistic for forked/mirrored repositories, shared history, or vendored/subtree commits, which is a common real-world topology). This is a real but conditional path — it depends on Shipit's multi-org deployment mode and on some SHA-sharing relationship between attacker- and victim-controlled repositories; it is not exploitable in the common single-organization deployment.

### Recommendation
Scope every inbound webhook handler's data lookups to the same repository/organization the request was verified against (not merely event-type dispatch). At minimum, `StatusHandler` (and any handler using `Commit.where(sha:)` without a `repository`/`stack` filter) should restrict results to `stacks` derived from `payload.dig('repository', 'full_name')` the same way `PushHandler`/`Handler#stacks` already does, and/or the controller should pass the verified organization identity down to handlers so they can assert `commit.stack.repository.owner == verified_organization` before mutating state.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own GitHub App/`webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications").
2. Ensure a stack tracking a repository under `org-b` has ingested a commit with SHA `X` (e.g., because `org-b`'s repo is a fork/mirror of a repo under `org-a`, or shares a vendored commit).
3. From `org-a`'s legitimate, correctly HMAC-signed webhook channel, send (or induce, via a push/status event on an `org-a` repo containing commit `X`) a `status` event payload: `{"sha": "X", "state": "success", "context": "ci/required", ...}`.
4. `WebhooksController#verify_signature` verifies the signature using `Shipit.github(organization: 'org-a')`'s secret — this succeeds because the request genuinely came from `org-a`'s GitHub App.
5. `StatusHandler#process` executes `Commit.where(sha: 'X')`, which matches the commit row under `org-b`'s stack (unscoped), and calls `create_status_from_github!`, writing a `success` status and potentially unlocking CI-gated deploy/merge behavior for `org-b`'s stack — despite the request never being authenticated for `org-b`. [10](#0-9)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
      end
    end
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

**File:** app/models/shipit/commit.rb (L360-386)
```ruby
    private

    def message_parser
      @message_parser ||= CommitMessage.new(message)
    end

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

**File:** app/models/shipit/status.rb (L18-34)
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
```

**File:** app/models/shipit/stack.rb (L151-196)
```ruby
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end

    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end

    def trigger_deploy(*args, **kwargs)
      if changed?
        # If this is the first deploy since the spec changed it's possible the record will be dirty here, meaning we
        # cant lock. In this one case persist the changes, otherwise log a warning and let the lock raise, so we
        # can debug what's going on here. We don't expect anything other than the deploy spec to dirty the model
        # instance, because of how that field is serialised.
        if changes.keys == ['cached_deploy_spec']
          save!
        else
          Rails.logger.warning("#{changes.keys} field(s) were unexpectedly modified on stack #{id} while deploying")
        end
      end

      run_now = kwargs.delete(:run_now)
      deploy = with_lock do
        deploy = build_deploy(*args, **kwargs)
        deploy.save!
        deploy
      end
      run_now ? deploy.run_now! : deploy.enqueue
      continuous_delivery_resumed!
      deploy
    end
```

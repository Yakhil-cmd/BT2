### Title
Commit-status webhook events are applied without repository scoping, letting a status verified for one organization/stack flip deploy-gating status on commits in a different stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/organization derived from `repository.owner.login` (or `organization.login`) in the payload [1](#0-0) . However, once the signature is accepted, the `status` event handler never re-checks that binding: `StatusHandler` does not even declare `repository` in its parameter schema and mutates state purely by matching `sha` against the entire `commits` table, with no scoping to the repository/organization whose secret validated the request [2](#0-1) . This breaks the equality "organization whose secret authenticated the request == repository/stack being written."

### Finding Description
1. `verify_signature` picks the `GitHubApp` (and thus the HMAC secret) for the request using `repository_owner`, i.e. `params.dig('repository','owner','login') || params.dig('organization','login')` [3](#0-2) . This only proves "this payload was signed by the GitHub App installation belonging to organization X."
2. The base `Handler` class does expose a `repository_name`/`stacks` helper that scopes to `Repository.from_github_repo_name(...)` [4](#0-3) , and most handlers (`PushHandler`, the `pull_request` handlers) correctly use it to scope their side effects to the repository named in the payload.
3. `StatusHandler` is the exception: its `params` block never requires `repository` at all, and `process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a query over the whole `commits` table, not filtered by stack, repository, or the organization that was authenticated [5](#0-4) .
4. Because a `Repository` can be tracked by multiple `Stack`s (one `Commit` row per stack, scoped `uniqueness: { scope: %i[environment] }`) [6](#0-5) , the same underlying git SHA legitimately exists as separate `Commit` records across every environment/stack for that repository (e.g. `staging` and `production`). A validly-signed `status` webhook — signed with the real webhook secret of the organization that owns the repository, i.e. no privileged secrets are stolen — triggers `Commit.where(sha:)` across *all* of those stacks simultaneously.
5. `create_status_from_github!` calls `add_status`, which fires `deployable_status` hooks and calls `stack.schedule_merges` whenever the state becomes `pending` or `success` [7](#0-6) . `schedule_merges`/deploy eligibility is gated by `release_status?`/`supports_fetch_deployed_revision?` etc., delegated from the cached deploy spec [8](#0-7) .

Net effect: a CI/status-reporting credential (e.g. a token scoped only to post statuses for a `staging` pipeline) that is legitimately authorized to report status for one stack ends up flipping the deploy-gating status for every other Shipit stack tracking the same repository/commit, including higher-trust `production` stacks that were supposed to require their own, independent status checks. This directly matches the required binding-violation class "an organization that authenticated versus the repository that is written" / "a stack a token authorises versus a stack it touches," because the authentication step only proves org-level provenance while the write (`Commit.where(sha:)`) is completely unscoped.

### Impact Explanation
This can produce an **unauthorized deploy**: if a `production` stack's deploy pipeline gates on `release_status?`/commit CI status, an attacker (or a benign but lower-trust integration) who can only cause a "success" status to be posted for a `staging`-scoped pipeline on a shared commit can cause that same status to be recorded against the `production` stack's identical commit, satisfying its deploy gate without the production-specific checks ever having run. This falls under the specified High/Critical impact bucket "an unauthorized deploy."

### Likelihood Explanation
Requires: (a) a repository tracked by more than one Shipit stack (a common, explicitly supported configuration — staging/production per-environment stacks on the same repo), and (b) any actor able to cause GitHub to emit (or, more directly, any actor holding a legitimately-scoped, lower-privilege commit-status-writing credential for that repository) a `status` webhook for a shared commit SHA. No `webhook_secret`, `api_clients_secret`, or Shipit session is needed — the organization's own real GitHub webhook signature is used exactly as GitHub sends it; the bug is purely that `StatusHandler` fails to scope by repository once the org-level signature is verified.

### Recommendation
In `app/models/shipit/webhooks/handlers/status_handler.rb`, require the `repository` object in the parameter schema (as the other handlers do) and scope the `Commit` lookup to the repository/stacks resolved from `params.repository.full_name` (i.e., reuse `Handler#stacks`/`repository_name`) instead of an unscoped `Commit.where(sha: params.sha)` query, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or equivalent, so a status event can only affect commits belonging to the repository actually named (and authenticated) in that payload.

### Proof of Concept
1. Configure Shipit with `myorg/myrepo` tracked by two stacks: `staging` (environment: staging) and `production` (environment: production). Both stacks sync commits from the same GitHub repository, so the same push produces a `Commit` row with identical `sha` in each stack.
2. A legitimate, narrowly-scoped CI integration (only intended to report status on the `staging` pipeline, e.g. a deploy key or status-only GitHub App token restricted to the staging branch/environment) posts a normal GitHub `status` webhook event for commit `abc123` with `state: "success"`. GitHub signs this with the real webhook secret of `myorg` — no secret leak needed.
3. `WebhooksController#verify_signature` validates the signature against `myorg`'s GitHub App config and passes [9](#0-8) .
4. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, which returns **both** the `staging` and `production` stacks' `Commit` rows for that SHA, and calls `create_status_from_github!(params)` on both [5](#0-4) .
5. The `production` stack's commit is now marked `success` and `stack.schedule_merges` is invoked [10](#0-9) , even though no production-specific CI/status check for that commit was ever run — enabling an unauthorized deploy pathway on `production`.

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

**File:** app/models/shipit/stack.rb (L96-99)
```ruby
    validates :repository, uniqueness: {
      scope: %i[environment], case_sensitive: false,
      message: 'cannot be used more than once with this environment. Check archived stacks.'
    }
```

**File:** app/models/shipit/stack.rb (L107-117)
```ruby
    delegate(
      :provisioning_handler_name,
      :find_task_definition,
      :release_status?,
      :release_status_context,
      :release_status_delay,
      :supports_fetch_deployed_revision?,
      :supports_rollback?,
      to: :cached_deploy_spec,
      allow_nil: true
    )
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

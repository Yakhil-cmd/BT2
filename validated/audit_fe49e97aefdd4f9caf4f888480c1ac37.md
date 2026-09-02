Notably `StatusHandler#process` at [1](#0-0)  matches on `Commit.where(sha: params.sha)` globally across all stacks, without any repository check at all — reinforcing that the org used for signature verification is never cross-checked against the data acted upon.

### Title
Cross-organization webhook confusion allows unauthorized commit-status and sync writes to another org's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to validate a request against based on an attacker-controlled field of the *unverified* JSON body (`repository.owner.login` or, as a fallback, `organization.login`), before the signature over that same body has been checked. The handlers dispatched afterward (`PushHandler`, `StatusHandler`) act on a *different* field of the same body (`repository.full_name`, or no repository scoping at all) to decide which `Stack`/`Commit` to mutate. Because the field used to pick the verifying secret is never bound to the field used to pick the target repository, a request that authenticates as one (weakly configured) organization can write state belonging to a completely different, properly configured organization.

### Finding Description
`Shipit.github(organization: repository_owner)` in [2](#0-1)  looks up the per-organization `GitHubApp` config using `repository_owner`, itself parsed straight from the raw, not-yet-verified body: [3](#0-2) . `GitHubApp#verify_webhook_signature` then explicitly treats an unset `webhook_secret` as automatically valid: `return true unless webhook_secret` in [4](#0-3) . The multi-organization config schema documented in `docs/setup.md` and exercised in `test/dummy/config/secrets_double_github_app.yml` explicitly allows one organization to be configured with `webhook_secret: # nil` while another has a real secret, and `Shipit.github_app_config` in [5](#0-4)  resolves configs purely by the org name supplied by the caller — i.e. by attacker-controlled input in this flow.

After `verify_signature` passes, `WebhooksController#create` dispatches the entire (still attacker-controlled) body to the registered handlers: [6](#0-5) . `Handler#stacks`/`#repository_name` resolve the target using `payload.dig('repository', 'full_name')` — a field independent of the `repository_owner` used for signature selection: [7](#0-6) . `PushHandler#process` then finds any non-archived stack for that repo/branch and calls `stack.sync_github(expected_head_sha: params.after)`: [8](#0-7) , enqueuing `GithubSyncJob` which fetches and creates commits for that (potentially unrelated) stack: [9](#0-8) . `StatusHandler#process` is even less scoped — it updates statuses for `Commit.where(sha: params.sha)` across the entire installation with no repository ownership check at all: [1](#0-0) , and `Commit#create_status_from_github!`/`add_status` can flip a commit to a `success` status and trigger `stack.schedule_merges` / continuous-deployment scheduling: [10](#0-9) , [11](#0-10) .

**The equality broken**: the binding "organization whose secret authenticated this request" ≠ "organization/repository whose stacks/commits are mutated by the request". Concretely: `Shipit.github(organization: payload['repository']['owner']['login'])`'s validity says nothing about `payload['repository']['full_name']` or the sha-matched commits actually acted upon.

### Impact Explanation
An attacker only needs the engine to be configured for at least two GitHub organizations where one has a blank/no `webhook_secret` (an explicitly documented, supported configuration) or otherwise a weaker/known secret. By crafting `repository.owner.login`/`organization.login` to name that weak org while setting `repository.full_name` (push events) — or omitting/using an arbitrary `sha` (status events) — to target another organization's tracked stack/commit, the attacker can:
- Force spurious `GithubSyncJob` runs and commit creation for a stack they do not control (push events), and
- Forge arbitrary CI/commit statuses (`success`/`failure`) for any commit sha tracked anywhere in the installation, which can flip merge-readiness and trigger `schedule_merges`/continuous-deployment for an unrelated, properly-authenticated organization's stack (status events), effectively an unauthorized/forced deploy trigger without ever presenting that organization's `webhook_secret`.

This crosses the "unauthorized deploy" / cross-repository-write bar defined in scope.

### Likelihood Explanation
Requires only that the deployment operate in the documented multi-org webhook mode with at least one org lacking (or having a discoverable) `webhook_secret` — a configuration explicitly supported and documented (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`). No GitHub write access, session, or `ApiClient` token is needed; the attacker only sends a raw HTTP POST to the public `/webhooks` endpoint.

### Recommendation
Bind the field used to select/verify the webhook secret to the field used to resolve the mutated resource: after verifying the signature, re-derive the acting organization strictly from `repository.full_name`'s owner (or reject if they differ), and ensure `StatusHandler` scopes lookups by repository/organization rather than matching `sha` globally across all stacks.

### Proof of Concept
1. Configure two orgs, e.g. `secrets.github["orgtrusted"]` with a real `webhook_secret`, and `secrets.github["orgweak"]` with `webhook_secret: nil` (a supported configuration per `docs/setup.md`), each tracked by Shipit stacks.
2. POST to `/webhooks` with header `X-Github-Event: status`, no/garbage `X-Hub-Signature`, and body:
```json
{
  "organization": { "login": "orgweak" },
  "repository": { "owner": { "login": "orgweak" }, "full_name": "orgweak/whatever" },
  "sha": "<sha of a commit belonging to orgtrusted's tracked stack>",
  "state": "success"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgweak")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` for any signature value ( [4](#0-3) ).
4. `StatusHandler#process` finds the commit by `sha` regardless of the org used above and records a forged `success` status for `orgtrusted`'s stack, potentially triggering `schedule_merges`/continuous deployment ( [1](#0-0) , [12](#0-11) ) — all without ever presenting `orgtrusted`'s webhook secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** lib/shipit.rb (L196-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L331-386)
```ruby
      if merge_request&.merged?
        merge_request.merge_requested_at
      else
        created_at
      end
    end

    def lock(user)
      update!(
        locked: true,
        lock_author_id: user.id
      )
    end

    def self.lock_all(user)
      update_all(
        locked: true,
        lock_author_id: user.id
      )
    end

    def unlock
      update!(locked: false, lock_author: nil)
    end

    def recently_pushed?
      created_at > RECENT_COMMIT_THRESHOLD.ago
    end

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

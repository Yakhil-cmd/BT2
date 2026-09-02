This confirms the key finding. The `StatusHandler` global cross-stack lookup is the strongest analog to the LPDA bug: the "sale ended" trigger (here, the deploy-triggering/status-transition logic) fires based on an identifier (`sha`) that isn't actually bound to the entity the signature verification authorized (the repository/organization owning the webhook). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Cross-repository commit-status spoofing via SHA-collision in `StatusHandler` triggers unauthorized deploys - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the GitHub organization/app derived from the payload's `repository.owner.login`, using that org's `webhook_secret`. However, once the signature is accepted, `Shipit::Webhooks::Handlers::StatusHandler#process` never checks that the commit it updates belongs to the repository that was actually authenticated — it looks up commits by `sha` alone, across the entire Shipit instance.

### Finding Description
Every other webhook handler resolves the target via the base `Handler#stacks` method, which scopes lookups to `Repository.from_github_repo_name(repository_name)` — i.e., the repository named in the (signature-verified) payload [7](#0-6) . `StatusHandler`, however, bypasses this entirely:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

The binding that should hold is: `organization authenticated by verify_signature == repository whose commit is written`. Instead the handler substitutes a much weaker binding: `sha string equality across all stacks in the Shipit instance`, regardless of which organization's webhook secret validated the payload.

`Commit` rows are shared by `sha` across every `Stack`/`Repository` tracked by the Shipit instance (there's no uniqueness constraint tying `sha` to a single repository) [8](#0-7) . Any organization that operates its own legitimately-configured GitHub App/webhook secret in this multi-tenant Shipit deployment (as documented for `Shipit.github(organization:)` multi-org support) can send a `status` webhook, correctly signed with *its own* secret, but specifying a `sha` that also exists in a *different* organization's stack (e.g., because of a shared upstream history, a cherry-picked/rebased commit, a fork, or simply because the attacker's org previously pushed the exact same commit into one of its own tracked repos and predicted/observed the victim's commit sha via public GitHub activity). Because `Commit.where(sha:)` is global, `create_status_from_github!` is invoked against the victim stack's commit as well.

`create_status_from_github!` → `add_status` unconditionally fires `commit_status`/`deployable_status` hooks and, critically, calls `schedule_continuous_delivery` whenever the new state is `pending` or `success` [4](#0-3) , and `Status#schedule_continuous_delivery` invokes `commit.schedule_continuous_delivery` on `after_commit` [5](#0-4) , which — if the victim stack has `continuous_deployment` enabled and the commit is otherwise deployable — enqueues a real deploy via `ContinuousDeliveryJob` [6](#0-5) .

### Impact Explanation
An attacker who legitimately controls a webhook secret for *any* GitHub organization tracked by a shared, multi-tenant Shipit instance can forge CI status ("success") for a commit belonging to a *different* organization's stack, as long as they can produce/predict a matching `sha`. This can push a victim stack's commit into a "deployable" state and trigger continuous delivery, resulting in an unauthorized deploy of code the victim never intended to ship at that time — this breaks the organization-authenticated-vs-repository-written binding and crosses a genuine tenant/authorization boundary within the engine (`app/controllers/shipit/webhooks_controller.rb` establishes only org-level identity, not repository-level authorization for `StatusHandler`).

### Likelihood Explanation
This requires the attacker to already operate a validly configured GitHub App/webhook secret for some organization onboarded to the same Shipit instance (a realistic scenario for shared/internal multi-tenant Shipit deployments, as explicitly supported by the "Using Multiple Github Applications" configuration) and to know or engineer a commit SHA collision with the victim's tracked commit (e.g. via shared open-source history, forks, or vendored/cherry-picked commits, which are common). It does not require compromising the victim's secret, a Shipit session, or any `ApiClient` token.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository derived from the verified webhook payload, mirroring the base `Handler#stacks` pattern, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This restores the binding between the authenticated organization/repository and the commit that is mutated.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per documented multi-org support).
2. `org-b` has a stack tracking a commit with sha `S` (e.g., because it shares history/a fork with `org-a`'s repository, or the attacker deliberately pushes a commit with a colliding tree such that Shipit records the same `sha` under both stacks — trivial if both orgs happen to share the same upstream commit).
3. Attacker, controlling `org-b`'s legitimate webhook secret, POSTs a `status` event to `/webhooks` with `repository.owner.login = "org-b"` (so `verify_signature` succeeds using `org-b`'s secret) but `sha: S` and `state: "success"`.
4. `WebhooksController#verify_signature` accepts the payload (correctly signed by `org-b`). `StatusHandler#process` runs `Commit.where(sha: S)`, which returns the commit(s) in **both** `org-a`'s and `org-b`'s stacks.
5. If `org-a`'s stack has `continuous_deployment: true`, the newly created "success" status transitions the commit to deployable and schedules `ContinuousDeliveryJob`, deploying `org-a`'s code without any authorization from `org-a`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

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

**File:** app/models/shipit/commit.rb (L91-103)
```ruby

    def self.by_sha(sha)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (too short)" if sha.to_s.size < 6

      commits = where('sha like ?', "#{sha}%").take(2)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (matches multiple commits)" if commits.size > 1

      commits.first
    end

    def self.by_sha!(sha)
      by_sha(sha) || raise(ActiveRecord::RecordNotFound, "Couldn't find commit with sha #{sha}")
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

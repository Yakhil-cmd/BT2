### Title
Webhook signature is verified against the payload's claimed organization while the event handlers act on data that is never covered by that binding, allowing cross-repository status forgery and unauthorized deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based solely on the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON payload, but the handlers that actually mutate state (in particular `StatusHandler`) never re-check that this organization matches the repository/commit being written to. This breaks the intended binding `organization authenticated == repository/commit written`.

### Finding Description
`WebhooksController#verify_signature` picks the `github_app` (and therefore the `webhook_secret` used to validate `X-Hub-Signature`) using `repository_owner`, itself derived directly from the JSON body: [1](#0-0) [2](#0-1) 

Once the signature is accepted, `create` dispatches the full, unvalidated JSON payload to the registered handlers for the event type: [3](#0-2) 

Most handlers scope their effect through the base `Handler#stacks`/`repository_name` helper, which is keyed off `payload.dig('repository', 'full_name')`: [4](#0-3) 

`repository.owner.login` (used to select the verification secret) and `repository.full_name` (used to select what gets written) are two independent, attacker-controlled JSON fields in the same request body — nothing ties them together. Critically, `StatusHandler` doesn't even use `repository.full_name`; it resolves target records purely by commit SHA, globally, with no repository/stack scoping at all: [5](#0-4) 

Since `Commit` belongs to a `Stack`/`Repository` but `StatusHandler` queries `Commit.where(sha: params.sha)` across the whole installation, any commit sha that happens to exist in **any** tracked stack (including ones belonging to organizations completely unrelated to the one that authenticated the webhook) will have a `Status` created for it. A newly created `success` status directly triggers continuous delivery: [6](#0-5) [7](#0-6) 
which, if the target stack has `continuous_deployment` enabled and the commit is otherwise deployable, results in `Stack#trigger_continuous_delivery` actually building and running a `Deploy`: [8](#0-7) 

This is exactly the class of bug described in the external report: a value (`repository.owner.login`) is used to establish trust (like `zeroHashes`/`initialize`), while a different, uncorrelated value (`sha`, entirely decoupled from `repository.full_name` and thus from the org that was authenticated) drives the actual state-changing operation (like `appendMessage`). The "initialization" (signature verification keyed by org) is bypassed for the actual write target because the write path never consults the verified field.

### Impact Explanation
An attacker who can produce one *valid* signature for *any* organization/App configured in this multi-tenant Shipit instance (e.g., because that org's `webhook_secret` is blank — which is the documented default/optional configuration — or because they legitimately control the webhook for their own onboarded organization) can forge a `status` event claiming success for a commit SHA belonging to a **different**, unrelated repository/stack that they have no access to. If that target stack has continuous deployment enabled, this results in an **unauthorized deploy** of an already-existing commit that never actually passed CI in that stack — satisfying the "Critical: unauthorized deploy" bar. It also allows spoofing CI status across repository boundaries more generally (marking blocking checks as passed), undermining the safety guarantees `Commit#deployable?`/`blocked?` are meant to provide.

### Likelihood Explanation
Exploitability depends on the attacker obtaining a valid signature for at least one org configured in the instance. Shipit's own documentation and default templates explicitly mark `webhook_secret` as optional (`webhook_secret: # nil` in `docs/setup.md`, `template.rb`, and default secrets files), so in any multi-organization Shipit install where even one org has not set a webhook secret, `verify_webhook_signature` returns `true` unconditionally for that org, and the described cross-repository status forgery becomes trivially reachable by an anonymous, unprivileged internet attacker who only needs to know/guess a commit SHA of a target stack (SHAs are often public on GitHub).

### Recommendation
Have `StatusHandler` (and any other handler resolving records without going through `Handler#stacks`) scope its lookup by the `repository.full_name` from the same verified payload, e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })`, and additionally have `WebhooksController#verify_signature` cross-check that `repository.owner.login` is consistent with `repository.full_name` before dispatch, rejecting payloads where the two disagree.

### Proof of Concept
1. Identify a Shipit-tracked repository/stack `victim-org/victim-repo` with `continuous_deployment: true`, and a real commit SHA `S` in it that has never received a passing status.
2. Identify any organization `weak-org` configured in the same Shipit instance whose `webhook_secret` is unset (default/optional per `docs/setup.md`), or otherwise obtain a valid signature for one configured org.
3. Send:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<valid-for-weak-org-or-blank-secret>
{
  "sha": "S",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "weak-org" }, "full_name": "weak-org/some-repo" }
}
```
4. `WebhooksController#verify_signature` resolves and accepts the signature using `weak-org`'s (absent) secret.
5. `StatusHandler#process` runs `Commit.where(sha: "S")`, finds the commit belonging to `victim-org/victim-repo` (unrelated to `weak-org`), and creates a `success` `Status` for it, which schedules `ContinuousDeliveryJob` and can trigger an unauthorized deploy of that commit in `victim-org/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

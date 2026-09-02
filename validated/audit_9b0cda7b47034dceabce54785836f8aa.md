### Title
Unauthenticated GitHub `status` webhook forgery triggers unauthorized continuous-deployment execution when `webhook_secret` is unset - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` delegates trust in an inbound webhook entirely to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` when no `webhook_secret` is configured for the organization [1](#0-0) . `docs/setup.md` explicitly documents the webhook secret as *optional* [2](#0-1) , meaning this "no verification" state is a supported, documented configuration, not a case of the host failing to mount the engine as documented. In that state, any unprivileged, unauthenticated actor can POST a forged `status` event to `/webhooks`, and the engine will treat it as GitHub-authentic and use it to drive a real deploy — the exact same class of bug as the reported `AlchemicTokenV2Base` issue: a state-mutating action (`mint`/`totalMinted`, here "commit is CI-green and continuous-deployment is triggered") is reachable through a path that isn't actually gated by the intended authorization primitive (the mint-ceiling check / the webhook HMAC signature).

### Finding Description
The binding that should hold is:
`verified_webhook_signature == true` **iff** `event was actually sent by GitHub for the configured organization`.

`GitHubApp#verify_webhook_signature` breaks this equality on one side: when `webhook_secret` is blank, it returns `true` for *every* request regardless of any `X-Hub-Signature` header content [1](#0-0) . `WebhooksController#verify_signature` only calls `head(422)` when `verified` is falsy, so this always-true path lets any payload through [3](#0-2) .

Once past this "verification," the dispatched `status` event is handled by `StatusHandler#process`, which looks up `Commit.where(sha: params.sha)` (an attacker-supplied SHA, only constrained to a SHA already known to Shipit, e.g. from the tracked branch history) and calls `commit.create_status_from_github!(params)` with an attacker-controlled `state` field [4](#0-3) . Creating a `success` status on a commit triggers `Commit#schedule_continuous_delivery`, which — if the stack has `continuous_deployment` enabled and the commit is otherwise `deployable?` — enqueues `ContinuousDeliveryJob`, ultimately calling `Stack#trigger_continuous_delivery` → `trigger_deploy`, which builds and runs a real `Deploy` task (executing the repository's `shipit.yml` `deploy` steps on the deploy host, using the app's own GitHub credentials) [5](#0-4) [6](#0-5) . This exact trigger path is asserted by the test suite itself for genuine webhook-originated status creation [7](#0-6) .

No `ApiClient` token, session, or any credential is required to reach `WebhooksController#create` — only that `webhook_secret` is unset for the relevant organization, which is an explicitly optional, documented configuration [8](#0-7) .

### Impact Explanation
This is analogous to the `lowerHasMinted()` finding: a supposedly-privileged action (mutate `totalMinted` / here, mark a commit as CI-passing and thereby command a real deployment) is reachable through an endpoint whose gate (`onlyWhitelisted` / here, HMAC signature verification) silently becomes a no-op under a normal, supported configuration state, letting any unprivileged caller flip it. The consequence matches the Critical bucket explicitly enumerated in scope: "an unauthorized deploy" — an external, unauthenticated attacker can force Shipit to execute the deploy pipeline (arbitrary shell commands defined in `shipit.yml`, run with the app's GitHub token) against a stack with continuous deployment enabled, without any real GitHub-verified CI success and without any credential.

### Likelihood Explanation
Likelihood is directly tied to a documented, non-default-hardening choice ("Webhook secret (optional)"), not to misconfiguration outside the documented setup flow. Any deployment that follows the setup guide literally and skips the optional webhook secret is exposed. The attack itself requires no more than crafting a JSON POST with a known commit SHA (obtainable from the public GitHub repository) and the `X-Github-Event: status` header — a trivial, unauthenticated HTTP request.

### Recommendation
Make `webhook_secret` mandatory (fail closed, not fail open) for any GitHub App configuration used to receive webhooks: `verify_webhook_signature` should reject (return `false`/raise) when `webhook_secret` is blank rather than short-circuiting to `true`. Additionally, `StatusHandler`/`Commit#schedule_continuous_delivery` should not treat externally-supplied webhook status state as sufficient on its own to trigger `trigger_continuous_delivery` without re-validating status/check-run state via an authenticated GitHub API call (defense in depth), similar to how the audit recommended removing/restricting `lowerHasMinted()` rather than trusting a caller-controlled decrement.

### Proof of Concept
1. Deploy Shipit per `docs/setup.md` without setting `webhook_secret` (documented as optional).
2. Enable `continuous_deployment` on a tracked stack; identify a known commit SHA in the tracked branch that is not yet the `last_deployed_commit`.
3. Send, with no authentication and no valid `X-Hub-Signature`:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<known commit sha>",
  "state": "success",
  "context": "ci/circle",
  "repository": {"full_name": "org/repo", "owner": {"login": "org"}}
}
```
4. `WebhooksController#verify_signature` accepts it because `webhook_secret` is blank [1](#0-0) .
5. `StatusHandler#process` creates a `success` status on the commit [9](#0-8) , `schedule_continuous_delivery` fires, and — mirroring the test at `test/models/commits_test.rb:233-243` — a real `Deploy` is enqueued and executed on the deploy host, entirely under attacker control of timing/target commit, with zero credentials presented.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
```ruby
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

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```

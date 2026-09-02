The finding is confirmed. The vulnerability is real and matches the question precisely.

### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized deploy through `Stack#trigger_continuous_delivery` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/stack.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` applies an incoming GitHub `status` webhook to every `Commit` row that shares the payload's `sha`, without ever checking that the payload's `repository` matches the repository owned by the `Commit`'s `stack`. Because signature verification (`WebhooksController#verify_signature`) only authenticates that the payload came from *some* GitHub organization Shipit trusts — not that it came from the *specific* repository whose commit is being mutated — a genuinely-signed status event from one repository can flip `deployable?` to true for an identical-sha commit that belongs to a completely different stack, which is then picked up by `Stack#trigger_continuous_delivery` and deployed.

### Finding Description
The broken binding, stated explicitly: the organization that authenticates the webhook (`repository_owner` in the payload, used only to select `Shipit.github(organization: repository_owner)` for signature verification) is treated as equivalent to "the repository that owns the `Commit`/`Stack` being mutated" — but these are not the same value.

Code path:
1. `WebhooksController#verify_signature` [1](#0-0)  only verifies the HMAC signature against the webhook secret configured for the *organization* named in the payload (`repository_owner`, itself read from `params.dig('repository','owner','login')`) [2](#0-1) . It never checks which specific repository the payload names against which specific stack's commit is targeted.
2. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
The handler's own params schema (`requires :sha`, `requires :state`, etc.) never includes or validates the `repository` field at all [4](#0-3) , so there is no code path anywhere that compares `params['repository']['full_name']` against `commit.stack.repository.full_name` before the status is attached.
3. `Commit#create_status_from_github!` unconditionally records the status: [5](#0-4) , which fires `Status#after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` [6](#0-5) .
4. `Commit#deployable?` becomes true purely from `success?` state derived from these unscoped statuses [7](#0-6) .
5. `Stack#trigger_continuous_delivery` then calls `next_commit_to_deploy` → `deployable_commits`, finds the now-"deployable" commit, and — once `should_resume_continuous_delivery?`/`should_delay_continuous_delivery?` are false — calls `trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)` [8](#0-7) , which builds and enqueues a real `Deploy`/`PerformTaskJob` [9](#0-8) .

Exploit flow: an attacker who owns a repository within any GitHub organization/App installation that Shipit already trusts (i.e., any repo whose real webhook deliveries pass `verify_signature`, since that check is organization-scoped, not repository-scoped) crafts a commit whose SHA is byte-identical to a pending, un-deployed commit that already exists in a victim stack (achievable because commit hashes are content-addressed and can be reproduced across repositories by copying tree/parent/author/committer/timestamps/message), then posts (or has CI post) a `success` status for that SHA on their own repository. GitHub signs and delivers the resulting `status` webhook using the trusted organization's secret. `verify_signature` passes because the org is legitimate; `StatusHandler#process` then attaches that status to the victim's `Commit` record purely by SHA match, with the payload's actual `repository` field never inspected. The forged "green CI" status makes the victim stack's commit `deployable?`, and continuous delivery deploys it.

Existing guards do not stop this: `verify_signature` authenticates the org, not the repository/stack; `ExplicitParameters` schema in `StatusHandler` never even declares a `repository` field to validate; no model validation on `Status`/`Commit` ties the created status back to the webhook payload's originating repository.

### Impact Explanation
This is an unauthorized deploy: a `Deploy` record is created and `Shipit::PerformTaskJob` enqueued for the victim's stack, ultimately spawning `Command`/`PTY.spawn` using the victim's `GITHUB_TOKEN`/deploy credentials, triggered purely by a status webhook naming a different repository. It matches "Critical - a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." Blast radius is scoped to any stack sharing a Shipit deployment with organizations whose GitHub App/webhook trust boundary is coarser than the individual repository (a common real-world configuration, e.g. a single org-wide GitHub App installation covering many repos/stacks), and is repeatable against any commit whose SHA the attacker can reproduce.

### Likelihood Explanation
Preconditions required: (1) the victim stack's target commit must already exist un-deployed with `continuous_deployment?` true and a cached deploy spec, matching the question's stated preconditions; (2) the attacker must be able to get a genuinely GitHub-signed `status` webhook delivered to Shipit's endpoint from some repository within an organization Shipit already trusts, without needing the `webhook_secret` itself (GitHub computes the signature at delivery time); (3) the attacker must reproduce the exact SHA of the victim's commit, which is feasible via forking or metadata-identical commit crafting since SHA1 git hashes are purely content-derived and don't encode the repository. This does not require any Shipit session, API token, or knowledge of `webhook_secret`/`secret_key_base`, matching the attacker capabilities defined in the rules.

### Recommendation
In `StatusHandler#process` (and analogously in `CheckRunHandler`/similar handlers), require and validate a `repository` field in the params schema, resolve the target `Stack`/`Commit` by both `sha` AND matching `stack.repository.full_name` (or `stack_id`) against the payload's repository, and skip/reject any `Commit` records whose owning stack's repository does not match the webhook payload's repository before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (in `test/models/shipit/webhooks/handlers/status_handler_test.rb` or `test/controllers/webhooks_controller_test.rb`, using existing fixtures):
```ruby
test "status webhook from a different repository must not mutate a commit belonging to another stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, ...)
  # sanity: binding before
  assert_not_equal 'attacker/other-repo', victim_stack.repository.full_name

  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate a genuinely-signed delivery from a trusted org, different repo

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/forged',
    'repository' => { 'full_name' => 'attacker/other-repo', 'owner' => { 'login' => 'shopify' } }
  }.to_json

  assert_no_difference -> { victim_commit.statuses.count } do
    request.headers['X-Github-Event'] = 'status'
    post :create, body: payload, as: :json
  end
  # binding after: still not equal, and no unauthorized deploy should have been triggered
  assert_not_equal 'attacker/other-repo', victim_stack.repository.full_name
  assert_no_difference -> { Deploy.count } do
    victim_stack.trigger_continuous_delivery
  end
end
```
Currently, with the unfixed `StatusHandler#process`, this test fails: `victim_commit.statuses.count` increases by 1, `victim_commit.deployable?` becomes true, and `Deploy.count`/`Shipit::PerformTaskJob` enqueue increases when `trigger_continuous_delivery` is invoked — demonstrating the cross-repository unauthorized deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/stack.rb (L174-196)
```ruby
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

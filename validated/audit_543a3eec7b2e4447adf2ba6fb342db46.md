### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but every event handler acts on the unrelated `repository.full_name` field, letting an org whose webhook secret is known forge status/push events for a different org's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GithubApp` (and thus the `webhook_secret` used for HMAC verification) using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). Every `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the actual repository/stack to mutate using a completely different field, `payload.dig('repository', 'full_name')`. The signature only proves "whoever sent this knows the secret configured for the org named in `repository.owner.login`" - it does not bind that secret to the `repository.full_name` value the handlers actually trust and act on.

### Finding Description [1](#0-0) 
selects the GithubApp config via `repository_owner`: [2](#0-1) 
and verifies the raw body with that org's secret: [3](#0-2) 

The base `Handler` class, used by every registered handler (`push`, `status`, `check_suite`, `pull_request`, etc., see [4](#0-3) ), resolves affected stacks via a *different* field of the same payload: [5](#0-4) 

Nothing ties `repository.full_name` to `repository.owner.login`/`organization.login`. Because the entire raw request body (including `repository.full_name`) is attacker-controlled prior to signing, and the HMAC only certifies "this body was produced by someone who knows the secret for the org named in `repository.owner.login`," an attacker who legitimately knows one org's `webhook_secret` (e.g., the admin of `OrgA` who created `OrgA`'s GitHub App and therefore chose/knows that secret, per the documented multi-org setup at `docs/setup.md`) can craft a signature that is valid for `OrgA` while setting `repository.full_name` to `OrgB/victim-repo` - a stack hosted under a completely different, unrelated GitHub organization on the same Shipit instance.

The `Handler#stacks` lookup by `Repository.from_github_repo_name(repository_name)` performs no cross-check against the verified organization, so the forged event is dispatched against `OrgB`'s stacks even though only `OrgA`'s secret was used to authenticate the request.

The blast radius is compounded because `StatusHandler` matches commits globally, not scoped to the verified organization or even to the target repository: [6](#0-5) 
`Commit.where(sha: params.sha)` matches any commit row across the whole Shipit installation by SHA alone, so a forged `status` event authenticated with `OrgA`'s secret can inject a fabricated CI status (e.g., `state: success`) onto a commit belonging to `OrgB`'s stack.

`PushHandler` similarly triggers a GitHub sync for any stack whose repo's `full_name`/branch matches the attacker-supplied values, using Shipit's own privileged GitHub App credentials to talk to GitHub: [7](#0-6) 

### Impact Explanation
A forged, cross-organization `status` event can satisfy `ci.require` gating on a stack the attacker has no authorization over, and continuous delivery consumes exactly that status data (`next_commit_to_deploy` -> `deployable_commits`, gated on `Commit#status`, and `trigger_continuous_delivery` -> `trigger_deploy`, see [8](#0-7)  and [9](#0-8) ). This lets an actor with only an unrelated org's webhook secret spoof a passing CI status that unblocks an unauthorized deploy/continuous-delivery run for a victim stack, matching the Critical "unauthorized deploy" impact bucket. It also allows forcing `sync_github`/`schedule_refresh_check_runs!` against arbitrary stacks using Shipit's own privileged GitHub credentials, an unauthorized cross-organization write of Shipit's internal state.

### Likelihood Explanation
Requires only that the attacker legitimately control (know) the `webhook_secret` of any one GitHub organization configured on a shared multi-org Shipit instance - a realistic scenario documented in `docs/setup.md`'s "Using Multiple Github Applications" section, since each org's admin creates their own GitHub App and picks/knows that org's secret. No repository write access, `ApiClient` token, or privileged Shipit account is needed; the `/webhooks` endpoint is unauthenticated apart from the HMAC check being bypassed via the org-scope confusion.

### Recommendation
Bind the verified organization to the acted-upon repository: after computing `repository_owner`/selecting the `GithubApp`, verify that `payload.dig('repository', 'full_name')`'s owner segment matches `repository_owner` (or the organization associated with the selected `GithubApp`/installation) before dispatching to any handler. Reject the webhook if these do not match.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as documented in `docs/setup.md`).
2. As the (low-privileged, non-Shipit-admin) creator of `OrgA`'s GitHub App, craft a `status` event JSON body:
```json
{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"},
  "sha": "<victim commit sha tracked under OrgB's stack>",
  "state": "success",
  "context": "ci/forged"
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and successfully verifies the signature against `OrgA`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `success` status on the victim commit under `OrgB`'s stack, even though the request was never authenticated for `OrgB`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/stack.rb (L210-243)
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

    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end

    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
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

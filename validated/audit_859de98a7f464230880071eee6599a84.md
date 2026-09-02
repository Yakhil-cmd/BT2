### Title
Cross-stack/cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits purely by bare SHA (`Commit.where(sha: params.sha)`), with no filter on the `repository` field of the incoming webhook payload or on the stack that owns the commit. Any status webhook whose signature is accepted by `Shipit::WebhooksController#verify_signature` will therefore write a `Status` row (and flip `blocked?`/`deployable?`) onto *every* commit record in the database that happens to share that SHA, regardless of which repository or stack the payload actually came from.

### Finding Description
The broken binding the code implicitly assumes is:
`commit.stack.github_repo_name == params.dig('repository', 'full_name')`

but this is never checked. The actual code is: [1](#0-0) 

`process` iterates `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` for every match, with `sha` being the only key. `Commit` rows are shared across all stacks in the instance (`belongs_to :stack`), and there is no `stack_id`/`repository` filter anywhere in this handler.

`create_status_from_github!` then updates `statuses` and recomputes `status`, and via `add_status` triggers `stack.schedule_merges` and `Hook.emit(:deployable_status, ...)` when the simple state changes: [2](#0-1) 

`blocked?` and `deployable?` are computed from the forced-in status: [3](#0-2) 

and `schedule_continuous_delivery` uses `deployable?` to trigger `ContinuousDeliveryJob`, gating an actual deploy: [4](#0-3) 

Existing guards do not close this gap:
- `verify_signature` in `WebhooksController` only checks the HMAC of the payload against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret`, where `repository_owner` is read straight out of attacker-controlled JSON (`params.dig('repository','owner','login')`): [5](#0-4) 
- `GitHubApp#verify_webhook_signature` explicitly **short-circuits to `true` if no `webhook_secret` is configured** for that organization: [6](#0-5) 
- None of these checks constrain which `Commit`/`Stack` rows the handler is allowed to mutate; they only gate whether the HTTP request is accepted at all, and the "which org's secret to use" decision is itself driven by attacker-supplied payload content.

Exploit flow: an attacker who controls (or can post signed statuses for) any repository configured in this Shipit instance — or any organization for which no `webhook_secret` was set — sends `POST /webhooks` with `X-Github-Event: status` and a JSON body `{"sha": "<shared-sha>", "state": "success", "context": "ci/e2e", "repository": {"owner": {"login": "<attacker-or-unconfigured-org>"}}}`. If any `Commit` row in the victim's stack shares that SHA (a realistic occurrence when multiple stacks/environments track the same underlying GitHub repository, or when history is shared across forks), `StatusHandler#process` will write the forged `success` status onto the victim's commit, which can flip `blocked?`/`deployable?` and trigger `ContinuousDeliveryJob` — an unauthorized deploy — or, with a forced `failure`, block a legitimate deploy.

### Impact Explanation
A payload that only authenticates for one repository/organization mutates commit/status state belonging to a different stack, satisfying the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy". Repeated calls let the attacker toggle `blocking_statuses` state arbitrarily for any commit sharing the SHA, potentially forcing or blocking continuous-delivery deploys on victim stacks they have no relationship to.

### Likelihood Explanation
The attacker needs: (1) the ability to get a `status` webhook signed/accepted (either via a repo/org they legitimately control that is configured in this Shipit instance, or via any org lacking a `webhook_secret`, which is a real, documented-as-optional configuration in `docs/setup.md`/`config/secrets.development.example.yml`), and (2) a SHA collision with a commit tracked by the victim stack. Exact SHA collision across unrelated content is infeasible, but shared commit history across multiple stacks/environments tracking the same GitHub repository (a common Shipit deployment pattern) makes this trivially satisfiable without any cryptographic collision. Given that, the attack is cheap and repeatable per request.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository indicated by the payload, e.g. resolve the target `Stack`(s) by `params.dig('repository','full_name')` first, then only update commits belonging to those stacks: `Commit.where(sha: params.sha, stack_id: matching_stack_ids)`. Additionally, `GitHubApp#verify_webhook_signature` should not treat a missing `webhook_secret` as automatically valid, and `repository_owner` used to select the verification key should be cross-checked against a registered `Repository`/`Stack` rather than trusted blindly from the payload.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_scope_test.rb
test "status handler must not affect commits from unrelated stacks sharing a SHA" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(deploy_spec_cache: victim_stack.deploy_spec_cache.deep_merge(
    'ci' => { 'blocking' => ['ci/e2e'] }
  ))
  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit')

  attacker_stack = Shipit::Stack.create!(repository: shipit_repositories(:other), environment: 'attacker')
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'attacker commit')

  before = victim_commit.reload.blocked?

  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/e2e',
    'repository' => { 'full_name' => attacker_stack.repository.full_name,
                       'owner' => { 'login' => attacker_stack.repository.owner } }
  )

  after = victim_commit.reload.blocked?

  # Binding under test: victim_commit.deployable? must be unaffected by attacker_stack's payload
  assert_equal before, after, "status from unrelated repository must not change victim stack's blocked? state"
end
```
This test demonstrates that `Commit.where(sha:)` in `StatusHandler#process` matches and mutates `victim_commit` even though the webhook payload's `repository` points to a different, attacker-controlled repo/stack, proving the cross-tenant write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

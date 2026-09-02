### Title
Cross-repository commit-status forgery via global SHA lookup in `StatusHandler` enables unauthorized deploy trigger for a victim's Stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`verify_signature` in `WebhooksController` correctly binds a webhook's signature to the organization named in its own payload, so an attacker cannot forge a webhook *as* the victim organization. However, `StatusHandler#process` looks up commits to update purely by `sha`, with no repository scoping, so a webhook that is 100% legitimately signed by the *attacker's own* GitHub organization can still write a `success` status onto a `Commit` row belonging to the *victim's* Stack, as long as that commit's SHA also exists in a repository the attacker controls (trivial via forking the victim's public repo). This breaks the exact binding the question asks about — "org whose secret signed the request == org whose stack got deployed" — and, combined with `continuous_deployment: true` and (optionally) a `continuous_delivery_schedule`, results in an unauthorized `Deploy` being created for the victim's stack.

### Finding Description
The binding that should hold is: `repository_owner(params) == stack.repository.owner` for every `Commit` record mutated by a webhook. Trace:

1. `WebhooksController#verify_signature` derives the signing org strictly from the payload's own `repository.owner.login` (or `organization.login`) and verifies the signature against that org's secret [1](#0-0) [2](#0-1) . This only guarantees the payload was actually sent by the org named in the payload — it says nothing about which `Commit`/`Stack` rows get touched afterward.
2. `StatusHandler#process` updates every `Commit` in the entire database that shares the forged `sha`, without checking that the commit's stack/repository matches the org that signed the request: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) .
3. Git commit SHAs are content-addressed. If the attacker forks the victim's public repository (an action available to any unprivileged GitHub user), every pre-fork commit in the fork has the identical SHA as in the victim repo. The attacker's fork has its own legitimate webhook/App installation signed with the attacker's own org secret, satisfying `verify_signature` for the attacker's own org.
4. The attacker sends a `status` event from their own repo for that shared-SHA commit with `state: success`. This passes signature verification (correctly, for the attacker's own org) and is routed to `StatusHandler`, which then locates and updates the *victim's* `Commit` row (because `Commit.where(sha:)` is unscoped) and calls `create_status_from_github!` on it.
5. If the victim's Stack has `continuous_deployment: true`, the new successful status causes `schedule_continuous_delivery` to enqueue `ContinuousDeliveryJob.perform_later(stack)` [4](#0-3) . `ContinuousDeliveryJob#perform` gates only on `continuous_deployment?`, the optional `continuous_delivery_schedule.can_deploy?` time window, and `occupied?` — none of which re-validate webhook provenance [5](#0-4) . If a `continuous_delivery_schedule` exists, `can_deploy?` merely checks wall-clock time against a per-weekday window [6](#0-5) , which the attacker can trivially satisfy by timing the request. `trigger_continuous_delivery` then calls `next_commit_to_deploy` and `trigger_deploy` [7](#0-6) , producing a real `Deploy` for the victim's stack.

So the question's premise is confirmed but mis-attributed: the CD-schedule check does pass through when timed correctly, and the resulting Deploy is indeed indistinguishable from a legitimate one — but the broken control is not "only webhook provenance in the abstract." Provenance verification of the *signature* works correctly; the actual break is that `StatusHandler` never re-checks provenance against the *record being mutated* (repository/stack ownership), so a correctly-signed webhook from org A can still mutate org B's `Commit`/`Stack` state.

### Impact Explanation
An attacker who forks any victim repository configured in Shipit with `continuous_deployment: true` can, using only their own legitimately-signed webhook, mark an arbitrary shared-SHA commit as `success` on the victim's Stack and trigger an unauthorized `Deploy` (and, transitively, whatever deploy commands/PTY execution that Stack's deploy spec runs) — this is a payload for one repository mutating another repository's Stack/Commit/Task, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy." The blast radius covers every Stack across every tenant organization hosted on the same Shipit instance, since `Commit.where(sha:)` has no tenant/repository boundary at all.

### Likelihood Explanation
Preconditions: victim Stack must have `continuous_deployment: true` (a common, documented feature) and be tracking a commit whose SHA the attacker can reproduce (trivially achieved by forking the public repo before the target commit, or via any commit an attacker can reproduce byte-for-byte, e.g. an old shared history commit). The attacker needs no Shipit credentials, no GitHub org membership in the victim's org, and no knowledge of any secret — only their own GitHub App/webhook installation on their own fork, which is available to any GitHub user. Optional CD-schedule timing is attacker-controllable by simply waiting for/choosing the window. This is a low-cost, repeatable, cross-tenant attack.

### Recommendation
Scope commit-status webhook processing by repository, not just by SHA: `StatusHandler#process` should filter candidate commits by the stack's associated repository (matching `params.dig('repository', 'full_name')` or `repository_owner`) before calling `create_status_from_github!`, so a status update can only affect commits belonging to the same repository/organization that signed the webhook.

### Proof of Concept
```ruby
test "status webhook from a foreign repo cannot flip status/trigger deploy on another repo's identical-SHA commit" do
  victim_stack = shipit_stacks(:shipit) # repository "shopify/shipit-engine", continuous_deployment: true
  victim_stack.update!(continuous_deployment: true)
  shared_sha = victim_stack.commits.last.sha

  # Attacker's own repo/org, distinct from victim's, but shares a commit with identical sha (forked history)
  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/evil-fork', 'owner' => { 'login' => 'attacker' } }
  }

  Shipit.stubs(:github).with(organization: 'attacker').returns(stub(verify_webhook_signature: true))

  freeze_time do
    travel_to(Date.current.monday.at_beginning_of_day.advance(hours: 12)) # inside any default CD window

    assert_difference -> { Deploy.count }, +1 do
      post webhooks_url, params: payload.to_json,
        headers: { 'X-Github-Event' => 'status', 'X-Hub-Signature' => 'sig', 'CONTENT_TYPE' => 'application/json' }
      perform_enqueued_jobs
    end
  end

  new_deploy = victim_stack.deploys.last
  assert_equal shared_sha, new_deploy.until_commit.sha
end
```
This asserts the equality claimed broken: signature verified for org `attacker` (`repository_owner == 'attacker'`) yet `victim_stack.deploys.count` increases and `until_commit.sha` equals the attacker-forged commit's sha — proving the org that signed the webhook is not the org whose stack was deployed.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/deploy.rb (L327-331)
```ruby
    def schedule_continuous_delivery
      return unless stack.continuous_deployment?

      ContinuousDeliveryJob.perform_later(stack)
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```

**File:** app/models/shipit/continuous_delivery_schedule.rb (L25-35)
```ruby
    def can_deploy?(now = Time.current)
      # Make sure time is in the default time zone so weekdays match what is
      # stored in the database.
      now = now.in_time_zone(Time.zone)

      deployment_window = get_deployment_window(now.to_date)

      deployment_window.enabled? &&
        now >= deployment_window.starts_at &&
        now <= deployment_window.ends_at
    end
```

**File:** app/models/shipit/stack.rb (L211-229)
```ruby
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

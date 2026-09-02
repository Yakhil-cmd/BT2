### Title
`StatusHandler#process` writes CI status to commits across all repositories sharing a SHA, with no repository scoping check - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, which is a bare, cross-tenant lookup with no filter tying the write to the repository that authenticated the webhook [1](#0-0) . Because webhook signature verification only proves *which organization* sent the request — not which commit/stack the payload is allowed to touch — any onboarded, unrelated GitHub organization can flip CI state (`ci/smoke`, etc.) for a commit belonging to a completely different stack/repository, as long as it can guess or read that commit's SHA.

### Finding Description
The broken binding, stated as an equality that must hold but does not:

`commit.stack.repository.full_name == repository_owner` (the org/repo that produced a validly-signed webhook, computed in `WebhooksController#repository_owner` from `params.dig('repository','owner','login')`) [2](#0-1) .

Trace of the path:
1. `WebhooksController#verify_signature` looks up `Shipit.github(organization: repository_owner)` and validates the HMAC signature against *that organization's* webhook secret [3](#0-2) . This only proves the sending organization owns a valid webhook secret for itself — it says nothing about which stack/commit the enclosed JSON is entitled to affect. The attacker fully controls the JSON body (including the `sha`, `context`, and `state` fields) before signing it with their own org's secret.
2. `StatusHandler.params` requires only `sha`, `state`, and optional `context`/`description`/`target_url`/`branches` — it never requires or checks `repository` [4](#0-3) .
3. `process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped lookup across every stack/repository in the Shipit instance [1](#0-0) .
4. `Commit#create_status_from_github!` → `add_status` computes `deployable?`/`blocked?` transitions and, on a state change to `pending`/`success`, calls `stack.schedule_merges` and (via `after_commit`) `commit.schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` when `stack.continuous_deployment?` and `stack.deployable?` [5](#0-4) [6](#0-5) .

Exploit flow: the attacker owns (or controls) any GitHub organization/repository that Shipit has onboarded (a legitimate but unrelated tenant). They read a target victim commit SHA from the victim's public repository/commit history, then send `POST /webhooks` with header `X-Github-Event: status` and a body `{"sha": "<victim-sha>", "state": "success", "context": "ci/smoke", "repository": {"owner": {"login": "<attacker-org>"}}}`, signed with the attacker-org's own webhook secret. Signature verification passes because it only checks the attacker's own org's secret. `StatusHandler` then matches and mutates the victim's `Commit` record purely by SHA collision/knowledge, regardless of repository, and regardless of `review_stacks_enabled` on either side — the review-stack provisioning flag and the `provision?` precedence issue in `opened_handler.rb` are irrelevant to this path; they govern whether a *new* review stack gets auto-created, not whether an *existing* stack's commit status can be forged cross-repo.

Existing guards that fail to prevent this: `verify_signature` binds to organization only, not repo/stack [7](#0-6) ; the `ExplicitParameters` schema in `StatusHandler` never declares/validates a `repository` field to cross-check against the matched commit's stack; `drop_unhandled_event` and `check_if_ping` are unrelated; no model validation in `Commit`/`Status`/`Stack` re-derives or checks repository ownership before writing a `Status`.

### Impact Explanation
An attacker who controls any onboarded-but-unrelated GitHub organization can create a `Status` row on a victim's `Commit` for an arbitrary `context` (e.g. a status the victim's stack treats as `required_statuses`/`blocking_statuses`), causing `Commit#deployable?` to flip and triggering `stack.schedule_merges` / `ContinuousDeliveryJob` for a stack the attacker never authenticated against [8](#0-7) . This is a payload from one repository mutating another repository's stack/commit state, and it can drive an unauthorized deploy or unblock a merge — matching the Critical "payload for one repository mutating another's stack, commit... / unauthorized deploy, rollback or merge" category. The blast radius spans every tenant/repository hosted on the same Shipit instance, since the lookup is entirely global (`Commit.where(sha:)` with no stack/repo scope).

### Likelihood Explanation
Preconditions: the attacker needs (a) any GitHub org/repo already onboarded into Shipit with a valid webhook secret (a low bar for a multi-tenant Shipit instance since any repository maintainer, even of an unrelated/low-trust repo, can trigger this once their org's webhook is configured), and (b) knowledge of a target commit SHA in the victim's tracked stack (trivially available for public repositories, and often guessable/leaked for private ones via other channels). No Shipit session, API token, or GitHub App private key is required beyond the attacker's own legitimately-provisioned org webhook secret. The attack is fully repeatable and scriptable against arbitrary target SHAs/contexts once the attacker knows them.

### Recommendation
Scope the `StatusHandler` lookup to only affect commits belonging to stacks whose repository matches the webhook's authenticated `repository.full_name`/`repository_owner`. Require and validate a `repository` block in `StatusHandler.params`, and filter `Commit.where(sha: params.sha)` by joining/filtering on `stack.repository_full_name == params.repository.full_name` (or equivalent) before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "does not write a status onto a commit belonging to a different repository's stack" do
  victim_stack = shipit_stacks(:shipit) # repository = "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, author: shipit_users(:shipit))

  attacker_payload = ExplicitParameters::Params.new(
    sha: victim_commit.sha,
    state: "success",
    context: "ci/smoke",
    # simulate the fact that verify_signature only checked the *attacker's own org's* secret,
    # not that this repository owns victim_commit
  )

  assert_no_difference -> { victim_commit.reload.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.new(attacker_payload).process
  end
end
```
Currently this assertion fails: `StatusHandler#process` creates a `Status` on `victim_commit` regardless of which repository's webhook secret was used to authenticate the request, because `Commit.where(sha: params.sha)` at `app/models/shipit/webhooks/handlers/status_handler.rb:21` performs no repository/stack scoping.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

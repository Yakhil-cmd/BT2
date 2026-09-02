### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup allows unauthorized deploy/rollback trigger - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by bare SHA with no repository/stack scoping, then writes a GitHub status onto every matching `Commit` row regardless of which repository's webhook secret authenticated the request. Because commit SHAs are content-addressed and identical across forks/shared history, an attacker who owns any repository (and thus a valid webhook signature for their own org) can send a `status` webhook for a SHA that also exists in a victim's stack, flipping that commit's `ci/jenkins` status and, if the victim stack has continuous deployment / auto-merge configured to run as the configured bot identity, force a ship or a block.

### Finding Description
The broken invariant, stated as an equality that should hold but doesn't:

`commit.stack.github_repo_name == params.dig('repository','full_name')` (the repository that authenticated the webhook) is **not** enforced anywhere in the path, yet it is required for "a `ci/jenkins` status affects only the repository that authenticated it" to be true.

Trace:
- `Shipit::WebhooksController#create` parses the raw JSON body and dispatches to handlers for the event type; `verify_signature` only validates the HMAC signature against `Shipit.github(organization: repository_owner)`, i.e. it proves the payload was signed by *some* org's webhook secret matching `params.dig('repository','owner','login')` — it does **not** bind the payload to any specific commit or stack. [1](#0-0) 
- `StatusHandler#process` then executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a bare, unscoped SHA lookup across the entire `commits` table, not filtered by `stack_id` or repository. [2](#0-1) 
- `Commit#create_status_from_github!` writes into `statuses` and calls `add_status`, which recomputes `status`/`deployable?`/`blocked?` and, on a state change, triggers `stack.schedule_merges` and evaluates `schedule_continuous_delivery` (`deployable? && stack.continuous_deployment? && stack.deployable?` → `ContinuousDeliveryJob.perform_later(stack)`). [3](#0-2) [4](#0-3) [5](#0-4) 
- `deployable?` and `blocked?` are computed purely from the commit's own `statuses`/`stack.blocking_statuses`/`stack.required_statuses`, so flipping `ci/jenkins` to `failure` (or `success`) directly changes whether the victim stack considers the commit shippable. [6](#0-5) 

Exploit flow: The attacker owns a repository (their own fork/org) and can trigger a legitimately-signed `status` webhook from it (via their own CI integration or by having GitHub deliver it for an action on their own repo). They pick a SHA that is shared between their repository and the victim's tracked stack — this is trivially achievable because git commit hashes are content-addressed: any commit that exists unmodified in both the fork and the upstream/victim repo (e.g., pre-merge history, a shared base commit, or any commit copied byte-identically into the attacker's own repo) has the identical SHA in both. The attacker sends `context: ci/jenkins`, `state: failure` (or `success`) for that SHA. Because `Commit.where(sha:)` is repo-agnostic, this write lands on the victim stack's `Commit` row and mutates its deploy-relevant status, independent of which repository actually authenticated the webhook.

Existing guards do not stop this: `verify_signature` validates only that *some* org's secret signed the payload, not that the SHA belongs to that org's repo; `drop_unhandled_event`/`ExplicitParameters` only validate shape (`sha`, `state`, `context` are attacker-controlled strings, not existence/ownership checks); there is no `stacks` scope or `require_permission!` check inside `StatusHandler`.

### Impact Explanation
A payload legitimately signed for repository A can mutate `Commit`/`Status` state belonging to stack/repository B, changing `deployable?`/`blocked?` and, if the victim stack has `continuous_deployment?` enabled (auto-triggered deploys run under the configured bot identity, e.g. `Shipit.user`/bot_login), can force `ContinuousDeliveryJob` to ship attacker-influenced code, or conversely force a required-context failure that blocks legitimate deploys (denial of legitimate shipping is a control-integrity issue but the primary claimed impact — unauthorized deploy/rollback triggering across tenant boundary — matches the "payload for one repository mutating another's stack/commit" Critical category). This is repeatable against any stack whose commits share a SHA with a repository the attacker controls, and the blast radius spans all stacks/tenants hosted on the same Shipit instance.

### Likelihood Explanation
Preconditions: attacker must control (or be able to trigger deliveries from) at least one repository registered with the Shipit installation, and must know/produce a SHA shared with the victim stack's commit history — achievable via normal fork/PR workflows where pre-merge commits share SHAs with upstream, or any repo where the attacker deliberately replicates a known commit's tree/parent/metadata. No Shipit session, API token, or GitHub team membership is required — only the ability to have GitHub sign and deliver a `status` webhook for a repository the attacker owns, which is native GitHub behavior. This makes the attack low-cost and repeatable.

### Recommendation
Scope the `StatusHandler` lookup to the repository that authenticated the webhook, e.g. join `Commit` to `Stack`/`Repository` and filter `Commit.where(sha: params.sha).joins(stack: :repository).where(repositories: { name: ..., owner: ... })` using `params.dig('repository', 'full_name')`, rejecting or ignoring status updates for commits whose owning stack's repository doesn't match the payload's repository.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or similar, no live GitHub):
1. Create `repository_a` (`org/repo-a`) and `repository_b` (`org-victim/repo-b`), and `stack_a`/`stack_b` respectively, with `stack_b` configured with `required_statuses: ['ci/jenkins']`, `continuous_deployment: true`, and a `bot_login` bound to `Shipit.user`.
2. Create a `Commit` under `stack_b` with a known `sha` "deadbeef..." with no statuses (so `deployable?` is currently `false`/pending, and `stack_b.deployable?` doesn't schedule).
3. Assert precondition equality: `commit_b.stack.github_repo_name != 'org/repo-a'` (the attacker's repo) while `commit_b.sha == attacker_payload_sha`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new.call({'sha' => 'deadbeef...', 'state' => 'failure', 'context' => 'ci/jenkins', ...})` simulating a payload whose `repository.full_name` is `org/repo-a` (attacker-owned), bypassing/stubbing `verify_signature` as already-passed (since it only checks org A's secret).
5. Reload `commit_b` and assert `commit_b.statuses.last.context == 'ci/jenkins'` and `commit_b.deployable?`/`commit_b.blocked?` changed state, and/or assert `ContinuousDeliveryJob` was enqueued/not enqueued for `stack_b` as a direct result of a webhook that never authenticated against `repo-b`'s or `stack_b`'s webhook secret — demonstrating the cross-repository mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

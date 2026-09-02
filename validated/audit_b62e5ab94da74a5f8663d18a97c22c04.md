I have enough evidence to make a final determination.

### Title
Cross-repository status injection via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target commit(s) with a bare, repository-unscoped `Commit.where(sha: params.sha)` lookup and writes a GitHub status onto every matching row, regardless of which repository authenticated the webhook. Since GitHub's Statuses API lets any repository owner post a status for an arbitrary SHA string (it need not exist in their own repository history), an attacker who owns a repository tracked by Shipit can forge a `sonarqube`/`failure` status for a victim stack's commit SHA and flip that commit's `blocked?`/`deployable?` state.

### Finding Description
The broken binding is: `commit.stack_id == webhook.repository.stack_id` is assumed but never enforced.

- `WebhooksController#verify_signature` only checks that the payload's HMAC matches the webhook secret for `repository_owner` (the org derived from `params.dig('repository','owner','login')`) [1](#0-0) . It never ties the `sha` field inside the payload to that same repository.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
with no `WHERE stack_id = ...` / repository filter at all [2](#0-1) .
- `create_status_from_github!` writes the status unconditionally through `statuses.replicate_from_github!` [3](#0-2) .
- `Status::Common#blocking?` and `#required?` are computed purely from `context` membership in `commit.blocking_statuses`/`required_statuses`, which are stack-level config, not tied to the origin repo of the status [4](#0-3) .
- `Commit#blocked?` walks `stack.commits.reachable...any?(&:blocking?)`, so a single injected `failure` status with a blocking context flips `blocked?` for the whole undeployed range, and `deployable?` follows directly [5](#0-4) .

Exploit flow: attacker owns/operates a repository "attacker/repo" that is registered as a Shipit stack with its own GitHub App/webhook secret. Using the GitHub Statuses API against their own repository (which they have write access to), they set `sha` to the 40-character SHA of a commit that actually belongs to `victim/repo`'s tracked stack, `context: "sonarqube"`, `state: "failure"`. GitHub signs and delivers this webhook using the *attacker's own repo's* webhook secret, so `verify_signature` passes (it only validates the signature belongs to `repository_owner`, i.e., the attacker's org — it says nothing about whether the SHA inside the payload belongs to that org). `StatusHandler#process` then matches the commit row belonging to the *victim's* stack purely by `sha` string equality, and writes a `sonarqube: failure` status onto it. If `sonarqube` is present in the victim stack's `ci.blocking` config, `blocking?` becomes true for that status, `Commit#blocked?` becomes true for later undeployed commits, and `deployable?`/`schedule_continuous_delivery` are affected — blocking (or, by sending `state: success` in a later request, unblocking) deploys the attacker does not own.

No existing guard prevents this: `verify_signature` authenticates the sender's organization but not the SHA-to-repository binding; `ExplicitParameters` only validates payload shape (`sha`, `state`, `context` types), not ownership; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler`.

### Impact Explanation
An attacker who controls any repository tracked by Shipit (even a throwaway/personal one they register themselves) can write arbitrary CI status records — including for required/blocking contexts — onto commits belonging to any other tenant's stack, provided they can guess or observe the victim's commit SHA (SHAs are frequently public via GitHub UI/API and not secret). This lets them force `blocked?`/`deployable?` to flip for a repository that never authenticated the write, matching the "Critical — a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback" category. The attack is repeatable against any SHA/context pair and is not limited to one victim.

### Likelihood Explanation
Preconditions: the attacker needs at least one repository that is already registered as a Shipit stack (self-service in many Shipit deployments, or via any repo they administer that gets onboarded), and needs to know/guess a target commit SHA (routinely public). No Shipit session, API token, or webhook secret for the victim's org is required — only the attacker's own repository's legitimate GitHub-issued signature. The victim stack must have `ci.blocking` (or `ci.require`) containing the forged context for the effect to matter, which is exactly the scenario in the question (`blocking_statuses` configured). Attacker cost is low (one GitHub Status API call); feasibility is high; it is fully repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogous handlers) to only commits belonging to a stack whose repository matches the webhook's authenticated `repository.full_name`/`repository_owner`, e.g., join through `Repository`/`Stack` and filter `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { full_name: params.repository.full_name })`, instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
test "StatusHandler writes a status onto a commit belonging to a different repository/stack" do
  attacker_repo_payload = {
    sha: victim_commit.sha, # victim's commit SHA, guessed/observed, belongs to a different stack/repo
    state: "failure",
    context: "sonarqube",
    branches: [{ name: "master" }]
  }

  victim_stack.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'blocking' => 'sonarqube' }))

  refute_predicate victim_commit, :blocked?

  # Signature verification only checks that the payload matches ATTACKER's org secret,
  # not that the sha inside belongs to that org's repository.
  Shipit::Webhooks::Handlers::StatusHandler.new.call(attacker_repo_payload.stringify_keys)

  assert victim_commit.statuses.exists?(context: "sonarqube", state: "failure")
  assert_predicate victim_commit.reload, :blocked?
end
```
Assert the equality `commit.stack_id == attacker_repository.stack_id` before (false, unrelated stacks) and after (still false, yet the write occurred) to demonstrate the write happened despite no ownership relationship. [2](#0-1) [1](#0-0) [5](#0-4)

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

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```

### Title
Cross-repository status webhook bypasses `Commit#blocked?` deploy gate - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` updates the status of every `Commit` matching a given SHA across the entire installation, without scoping the lookup to the repository/stack named in the webhook payload. Since a git commit SHA is a hash of the commit's content and is identical across any repository (e.g., a fork) that contains that exact commit, an attacker who controls a repository sharing history with the victim's repo can push a webhook that flips the state of a `blocking` status context on the victim's commit, changing `Commit#blocked?` and therefore `Commit#deployable?` for an unrelated stack.

### Finding Description
The broken binding is: **the org that authenticates via `verify_signature` == the org owning the stack/commit whose blocking-status computation is mutated**. This should always hold but does not.

- `WebhooksController#verify_signature` derives the authenticating org strictly from the payload's `repository.owner.login` (or `organization.login`) field and verifies the signature against that org's GitHub App secret: [1](#0-0) , [2](#0-1) .
- This only proves the payload was signed by whoever owns the org named in the payload — it says nothing about which `Commit`/`Stack` records will actually be mutated.
- The base `Handler` class provides a `stacks` helper that *does* scope lookups by `repository_name` from the payload: [3](#0-2) . However, `StatusHandler#process` does not use it at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

- `Commit.where(sha: params.sha)` is a global, unscoped query across every stack in the Shipit instance. Any commit — belonging to any repository/stack — whose `sha` column equals the attacker-supplied `params.sha` gets its status updated.
- `create_status_from_github!` writes a new `Status` row tied to that commit's own `stack_id` (`statuses.replicate_from_github!(stack_id, github_status)`), so the injected status becomes a first-class status for the victim's stack: [5](#0-4) , [6](#0-5) .
- `Commit#blocked?` re-derives blocking state by scanning `stack.commits.reachable...any?(&:blocking?)`, and `Status::Common#blocking?` is `!success? && commit.blocking_statuses.include?(context)`: [7](#0-6) , [8](#0-7) . Once the attacker's injected `success` status for the blocking `context` lands on C1, C1 stops being blocking, and `C2.blocked?`/`C2.deployable?` flip.

**Exploit path**: A git commit's SHA is computed purely from its content (tree, parents, author/committer, message) and is independent of which repository hosts it. If the victim's repository is public (or the attacker otherwise gains access to an identical commit, e.g., via forking), the attacker can fork it, obtaining a local copy of commit C1 with the identical SHA. The attacker then triggers (or crafts, if they control any GitHub App/webhook delivery for their own org) a `status` event where `repository.owner.login` is the attacker's own org (so `verify_signature` succeeds against the attacker's own legitimately-configured GitHub App secret) but `sha` equals C1's SHA and `context`/`state` are set to satisfy `stack.blocking_statuses` with `success`. `StatusHandler#process` matches C1 by SHA regardless of the `repository` field in the payload and applies the status, which is exactly what the question's "proof idea" states — the payload's `repository` field never needs to name C2's stack's repository.

None of the listed guards intercept this: `verify_signature` only checks payload-vs-org signature consistency, not payload-repository-vs-matched-commit consistency; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not ownership; there is no `require_permission!`/`stacks` scoping check inside `StatusHandler`.

### Impact Explanation
A status payload legitimately signed for one repository/org can mutate `Status`/blocking-state for a commit belonging to a completely different stack, potentially owned by a different, unrelated GitHub organization/tenant. This directly matches the "Critical" category: *"a payload for one repository mutating another's stack, commit, task or team... or an unauthorized deploy."* Concretely it lets the attacker waive a safety gate (`blocking_statuses`) that a victim org relies on to prevent deployment of a commit range with missing/failing compliance or security checks (e.g. `soc/compliance`), enabling `C2.deployable?` to become true and an actual deploy to be triggered for the victim's stack. The attack is repeatable against any commit whose SHA the attacker can reproduce (any commit reachable via a public fork, or any commit the attacker can otherwise learn the SHA of, since `sha` is the only correlation key and it is not secret), across arbitrary tenants sharing the Shipit instance.

### Likelihood Explanation
Preconditions: `stack.blocking_statuses` non-empty (a documented, common configuration feature — `ci.blocking` in `shipit.yml`), and the target commit C1 must currently be "blocking" a later undeployed commit C2. The attacker needs: (1) their own repository connected to the same Shipit instance's GitHub App installation (to legitimately pass `verify_signature` for their own org) or an ability to send `status` webhooks for a repo they own that has a working GitHub App/webhook configured against this Shipit host, and (2) a commit sharing C1's exact SHA, most simply obtained by forking a public victim repository. Both are unprivileged actions available to any GitHub user. No secrets, sessions, or `Shipit.github_teams` membership are required. This is low-cost and fully repeatable.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to only commits belonging to stacks for the repository named in the payload, using the existing `stacks` helper (or joining through `Stack`/`Repository` on `repository_name`) instead of a bare `Commit.where(sha: params.sha)` across the whole installation. E.g. restrict the query to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or equivalent), so a status webhook can only affect commits whose stack's repository matches the authenticated org/repository from the payload.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/status_handler_test.rb` (or extend `webhooks_controller_test.rb`):

```ruby
test "status webhook for an unrelated repository flips blocked? for a victim stack sharing the same commit SHA" do
  # Victim setup: stack with blocking_statuses configured
  victim_stack = shipit_stacks(:shipit)
  victim_stack.stubs(:blocking_statuses).returns(['soc/compliance'])

  c1 = shipit_commits(:soc_second)          # blocking commit in victim stack, currently pending/missing
  c2 = shipit_commits(:soc_third)           # later undeployed commit in same stack

  c1.statuses.delete_all
  assert_predicate c1, :blocking?
  assert_predicate c2, :blocked?
  refute_predicate c2, :deployable?

  # Attacker's payload names an unrelated repository, but the sha collides with c1 (e.g. via fork)
  attacker_payload = {
    'sha' => c1.sha,
    'state' => 'success',
    'context' => 'soc/compliance',
    'repository' => { 'full_name' => 'attacker-org/attacker-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  c1.reload
  c2.reload
  refute_predicate c1, :blocking?          # side effect: victim commit's blocking status waived
  refute_predicate c2, :blocked?           # BEFORE: true, AFTER: false
  assert_predicate c2, :deployable?        # deploy gate bypassed with no request naming c2's repo
end
```

This demonstrates `C2.deployable?` flipping from `false` to `true` purely as a side effect of `StatusHandler.call` processing a payload whose `repository` field never names C2's stack's repository, confirming the binding equality ("authenticated org == mutated stack's owning org") is violated: [4](#0-3) [9](#0-8) .

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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```

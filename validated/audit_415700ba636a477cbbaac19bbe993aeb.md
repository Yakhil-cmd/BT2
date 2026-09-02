### Title
Cross-Repository Commit Status Forgery via SHA-Only Lookup Bypasses the Webhook Signature's Repository Binding - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler`, which processes GitHub `status` webhook events, resolves the target `Commit` records purely by `sha`, without any scoping to the repository/organization that the inbound webhook's HMAC signature actually authenticates. This breaks the binding: *the organization/repository that authenticated the webhook* must equal *the repository whose state is written*.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/secret used to validate `X-Hub-Signature` based on the organization named in the payload itself (`repository.owner.login` or `organization.login`), then verifies the whole raw body against that org's `webhook_secret`: [1](#0-0) 

This proves the request came from *some* organization/installation configured in Shipit (the one named in the payload), and that its repository/owner fields are authentic for that installation. However, `StatusHandler#process` never re-checks that the commit being updated actually belongs to the repository/stack named in that same payload — it looks the commit up by `sha` alone, across the entire `Commit` table (i.e., across every stack/repository/organization Shipit tracks): [2](#0-1) 

Compare with `Handler#stacks`, which correctly scopes lookups by `payload.dig('repository', 'full_name')`: [3](#0-2) 

`StatusHandler` does not use this scoping at all — `repository_name`/`stacks` are unused by it. Git commit SHA-1 IDs are content-addressed but not repository-addressed: the same SHA can legitimately (or intentionally, by an attacker who controls the exact tree/parent/author/committer/timestamps) exist as a commit object in two unrelated, independently-tracked repositories/stacks in the same Shipit instance. Since `Commit.where(sha: params.sha)` has no `stack_id`/repository filter, a validly-signed `status` webhook originating from Organization/Repo A (which the attacker legitimately controls and which is already onboarded into this Shipit instance) can update the recorded GitHub status of a commit that has the same SHA in Repo B, a completely different, unrelated stack the attacker does not control.

`Commit#create_status_from_github!` writes this forged status via `add_status`, which fires `deployable_status`/`commit_status` hooks and calls `stack.schedule_merges`: [4](#0-3) 

`Commit#deployable?` depends directly on stored status state, and `schedule_continuous_delivery` triggers automatic deployment once a commit is `deployable?` and the stack has `continuous_deployment?` enabled: [5](#0-4) [6](#0-5) 

Thus, a forged "success" status for a shared SHA can flip `deployable?` to true and cause an unattended `ContinuousDeliveryJob` to deploy a commit that never actually passed the victim organization's real CI.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary named in scope: the webhook signature only proves authenticity for the organization/repo named in the payload, but the actual database write (a commit's status, which gates deploy eligibility) is applied without checking that the target commit belongs to that same repository/stack. The result is an unauthorized write of deploy-gating state in a repository the attacker does not control, and — if continuous deployment is enabled on the victim stack — can produce an unauthorized deploy. This falls under the in-scope "High" impact category (escalation of authorization) and can reach "Critical" (unauthorized deploy) when continuous delivery is enabled on the affected stack.

### Likelihood Explanation
Exploitation requires: (1) the attacker to control (or have push access to) at least one GitHub repository that is already onboarded as a Shipit stack in the same multi-tenant Shipit instance — i.e., they can legitimately trigger real, validly-signed webhooks for their own repo; and (2) crafting/obtaining a commit whose SHA-1 collides with a commit SHA already recorded for another, victim stack. Since git commit hashes are computed deterministically over exact byte content (tree, parents, author/committer identities and timestamps, message), an attacker who can see a target commit's full metadata (e.g., a public commit on the victim's public repo) can reproduce a byte-identical commit object with `git commit-tree`, giving an identical SHA, then push/graft it into their own onboarded repo to trigger a legitimately-signed `status` (or push) event referencing that SHA. This is a realistic multi-tenant scenario (single Shipit deployment servicing many repos/orgs) but requires prior onboarding of an attacker-controlled repo, which somewhat limits likelihood; it does not require any Shipit credentials, session, or webhook secret access, satisfying "unprivileged attacker" scope.

### Recommendation
Scope all commit-affecting webhook handlers (in particular `StatusHandler`, and any future SHA-keyed handler) to the repository named in the verified payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Repository.from_github_repo_name(repository_name)` as `Handler#stacks` already does for `PushHandler`. Alternatively, scope `Commit` lookups by `stack_id` derived from the payload's `repository.full_name`, ensuring the entity whose state is mutated always matches the entity whose signature was verified.

### Proof of Concept
1. Shipit instance has two onboarded stacks: `victim-org/app` (with `continuous_deployment: true`) and `attacker-org/decoy` (attacker has push access, legitimately onboarded).
2. Attacker observes a public commit `C` in `victim-org/app` with SHA `deadbeef...` that is pending/unreviewed.
3. Attacker reconstructs an identical commit object (`git commit-tree` with matching tree, parent, author, committer, message/timestamps) so that hashing it yields the same SHA `deadbeef...`, and pushes it into `attacker-org/decoy`.
4. Attacker (or CI configured by attacker) posts a GitHub `status` webhook for `attacker-org/decoy` with `sha=deadbeef...`, `state=success`. This webhook is correctly signed with `attacker-org`'s legitimate webhook secret, so `WebhooksController#verify_signature` accepts it.
5. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')`, which also matches the commit `C` in `victim-org/app`, and calls `commit.create_status_from_github!(params)` on it — recording a forged "success" status for `victim-org/app`'s commit.
6. If `victim-org/app` has continuous deployment enabled, `Commit#schedule_continuous_delivery` now sees `deployable?` return true and enqueues an unauthorized deploy of commit `C`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/commit.rb (L365-386)
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

### Title
Cross-repository commit-status forgery via organization-scoped webhook signature not bound to the target repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb, app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify a webhook against based solely on `repository_owner` (an organization/owner login parsed out of the untrusted JSON body), then dispatches the *entire* verified payload to a handler that never re-checks that the organization which supplied the secret is actually the owner of the resource being mutated.

### Finding Description
The webhook signature is verified per-organization: `Shipit.github(organization: repository_owner)` picks the `GithubApp`/secret matching the owner login found in the payload, and `verify_webhook_signature` HMACs the raw body against that secret. [1](#0-0) [2](#0-1) 

This proves only that *some* organization onboarded on this Shipit instance signed the request — it does not prove the request concerns that organization's own repositories. `StatusHandler`, however, resolves its target purely by commit SHA, globally, with no repository/organization scoping at all: [3](#0-2) 

`Commit.where(sha: params.sha)` searches across **every stack/repository tracked by the Shipit instance**, not just repositories belonging to `repository_owner`. Because git commit SHAs are content-addressed and often guessable/discoverable (public repos, PR mirrors, forks, shared base commits), an organization "OrgA" that has legitimately installed the Shipit GitHub App (and thus knows/controls when OrgA's webhook secret is used to sign requests) can send a `status` event whose `repository.owner.login` is `OrgA` (satisfying `verify_signature`) but whose `sha` matches a commit belonging to a stack owned by an unrelated `OrgB` tracked on the same instance.

This breaks the intended binding:
`organization that authenticated (repository_owner used to pick the HMAC secret) == repository whose data is written (stack/commit actually mutated)`

The equality does not hold: `StatusHandler` never joins the target `Commit`/`Stack` back to `repository_owner`, so any org accepted by `verify_signature` can write a `Status` onto any commit hosted on the instance, exactly analogous to the reported bug where the vault-deposit code path (`BunniHub`) trusted that a rehypothecated deposit implied a corresponding balance increase without checking the actual invariant — here Shipit trusts that "signature verified for org X" implies "this event pertains to org X's data," without checking it.

### Impact Explanation
`Commit#status` (an aggregation of `statuses`) directly gates `deployable?`, and gates `schedule_continuous_delivery`/`schedule_merges`: [4](#0-3) [5](#0-4) 

By forging a `success` status on a commit belonging to a different tenant's stack, an attacker who only controls their own organization's webhook secret can cause that unrelated stack to mark a commit as CI-passing, triggering `stack.schedule_merges` and continuous-deployment queuing — i.e., an unauthorized deploy path is unlocked on a repository the attacker was never granted access to. This matches the "unauthorized deploy" Critical impact bucket, since it circumvents the CI/CD gate cross-tenant without any repository write access or Shipit session on the target stack.

### Likelihood Explanation
Likelihood is Medium: the attacker must (a) control an organization that has a working GitHub App/webhook secret configured on this multi-tenant Shipit instance (a normal, unprivileged-with-respect-to-other-tenants setup, not requiring any secret theft), and (b) know or guess a target commit SHA belonging to another tenant's stack — plausible for public repositories, shared upstream commits, or forks, which are common in review-stack/PR-based CI workflows this engine targets.

### Recommendation
`Handler#process` implementations that key off SHA-only or otherwise repository-agnostic identifiers (`StatusHandler`, `CheckSuiteHandler`, etc.) must scope their queries to the repository/organization that was actually verified for the request, not merely to a matching commit SHA anywhere in the database. Concretely, `StatusHandler#process` should intersect `Commit.where(sha: params.sha)` with `stack.repository`/`stack.repository.owner` matching `repository_owner`/`payload.dig('repository','full_name')`, mirroring the scoping already done in `Handler#stacks`/`Handler#repository_name`. More generally, `WebhooksController#verify_signature` should pass the verified `repository_owner` down to every handler so each handler can assert the owner of the mutated resource equals the authenticated owner before persisting anything.

### Proof of Concept
1. Attacker's org "OrgA" installs the Shipit GitHub App on a shared/multi-tenant Shipit instance and is issued a webhook secret `S_A` (legitimate, no privilege beyond OrgA).
2. Attacker discovers/guesses a commit SHA `deadbeef...` that exists in `OrgB`'s tracked stack (e.g., a public upstream commit both repos share, or a forked PR head).
3. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "repository": {"full_name": "OrgA/irrelevant-repo", "owner": {"login": "OrgA"}}
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` using OrgA's own secret and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner = "OrgA"`, fetches OrgA's app, and successfully verifies the signature. [6](#0-5) 
6. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, which matches the commit in `OrgB`'s stack (no ownership check), and calls `commit.create_status_from_github!(params)`, writing a forged `success` status onto `OrgB`'s commit. [3](#0-2) 
7. If this makes the commit `deployable?` and the target stack has `continuous_deployment?` enabled, `schedule_continuous_delivery`/`schedule_merges` is triggered for `OrgB`'s stack purely from OrgA's forged webhook. [7](#0-6)

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

**File:** app/models/shipit/commit.rb (L379-385)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
```

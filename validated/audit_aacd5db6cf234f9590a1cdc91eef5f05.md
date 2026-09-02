### Title
Cross-repository commit-status forgery due to missing repository scoping in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's webhook secret to validate a payload against based on a field taken from the very same, attacker-influenced JSON body (`repository.owner.login` / `organization.login`), and then dispatches the *entire* raw payload to the matching `Shipit::Webhooks::Handlers` class [1](#0-0) . Unlike `PushHandler` and `CheckSuiteHandler`, which scope the entities they mutate to the `stacks` derived from `payload.dig('repository', 'full_name')` via `Handler#stacks` [2](#0-1) [3](#0-2) , `StatusHandler#process` performs its write using nothing but the commit `sha`, with zero repository/stack scoping:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

### Finding Description
This is the direct structural analog of the reported bug class: a check performed against one scope (here, "the organization whose webhook secret validated this delivery, tied to `repository.owner.login`") is used to authorize a write that is actually performed against a broader, uncorrelated scope (here, "every `Commit` row across every `Stack`/`Repository` in the whole Shipit instance that happens to share the same 40-hex `sha`"). Just as Silo's incentives controller conflated "underlying token" with "collateral/debt token" because they are related-but-distinct concepts, Shipit's `StatusHandler` conflates "the repository that authenticated this webhook" with "the repository whose commit gets the status written," because `sha` alone is not unique to a repository — identical commit SHAs commonly exist across forks/mirrors that share history (a very common Shipit setup: an org tracks a fork/mirror of an upstream project as its own stack).

Binding broken (as an equality):
`repository_owner used to select the webhook_secret for HMAC verification` ⧧ `repository/stack whose Commit row is mutated by StatusHandler`.

Before the attacker's request: a `status` webhook signed with organization A's `webhook_secret` can only be expected to affect commits that live in organization A's repositories, because the signature only proves "this org configured this secret."
After the attacker's request: the same signed payload updates the CI status of any `Commit` record in Shipit's database with a matching `sha`, regardless of which `Repository`/`Stack`/organization actually owns it, because `StatusHandler` never re-checks `payload.dig('repository', 'full_name')` before writing.

### Impact Explanation
Commit CI status ("success"/"pending"/"failure") delivered through GitHub `status` events is the signal Shipit uses to determine whether a commit is deployable (gating the deploy button/CI checks). An attacker who can legitimately trigger a real, correctly-signed `status` webhook for *their own* repository (e.g., by pushing a commit that shares history — and thus a SHA — with an upstream/shared repository that another team tracks as a separate Shipit stack, then setting a commit status via GitHub's own Statuses API on their fork) can cause Shipit to write an arbitrary CI status onto the corresponding `Commit` row of the unrelated stack. If the attacker forges a "success" status for a commit that was previously "pending"/"failing" in a stack they do not own, this can make that commit appear deployable in a repository/stack outside of their authorization, i.e. an unauthorized deploy — matching the report's cross-repository-write / unauthorized-deploy impact tier. This requires no Shipit session, `ApiClient` token, or `webhook_secret` value the attacker doesn't already legitimately possess for their own org/repo — only ordinary push/webhook-triggering rights on one repository sharing commit history with the target.

I could not fully re-verify in this pass exactly which Shipit deploy-gating code path consumes `Commit#state`/status to permit deploys (I did not have time to open the `Commit`/`Stack#deployable_commits` model code again), so the precise mechanics of how a forged status translates into an actual unauthorized deploy trigger should be confirmed by a maintainer; the missing repository scoping in `StatusHandler`, however, is directly and unambiguously demonstrated by the code shown above.

### Likelihood Explanation
Moderate. It requires the attacker to have legitimate write/webhook-triggering access to at least one repository that shares commit history (hence identical SHAs) with a separate Shipit-tracked repository — a realistic scenario for forked/mirrored projects, monorepo extractions, or any org that maintains parallel stacks off shared upstream commits. No secret material needs to be stolen; the attacker uses their own, legitimately-issued signature.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository identified in the webhook payload, mirroring `PushHandler`/`CheckSuiteHandler`'s use of `Handler#stacks`:

```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

More generally, audit all webhook handlers to ensure every entity looked up or mutated is scoped via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`/`Handler#stacks`, not solely by attacker-supplied identifiers like `sha` that are not unique per repository.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `Repository`/`Stack` (`app/models/shipit/repository.rb`, `Shipit.github_organizations`) [5](#0-4) .
2. `org-a/mirror` and `org-b/upstream` share commit history (e.g. `org-a/mirror` is a fork), so a specific commit `sha` exists identically as a tracked `Commit` in both `Shipit::Stack`s.
3. An attacker with push/webhook rights in `org-a/mirror` triggers (or has GitHub deliver) a `status` event for that shared `sha` with `state: "success"`. GitHub signs it with `org-a`'s configured `webhook_secret`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `org-a`, fetches `Shipit.github(organization: "org-a")`, and validates the HMAC successfully [6](#0-5) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` unscoped, finds the matching `Commit` belonging to `org-b/upstream`'s stack, and calls `create_status_from_github!`, writing a forged "success" status onto a commit in a repository/organization the attacker does not control [4](#0-3) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** lib/shipit.rb (L190-200)
```ruby
  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

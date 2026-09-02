### Title
Cross-repository CI status forgery via SHA-only commit lookup in `StatusHandler` bypasses per-repository webhook authorization - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authorizes an inbound GitHub webhook based on the *organization* derived from the payload (`repository.owner.login` / `organization.login`), which selects the GitHub App/webhook secret used to validate the HMAC signature. [1](#0-0) [2](#0-1)  Once verified, however, `StatusHandler#process` writes the CI status to **any** `Commit` record in the entire Shipit installation whose `sha` matches the payload, with no repository/stack scoping check at all: [3](#0-2)  This breaks the equality that should hold: `organization authenticated by verify_signature == repository whose Commit record is written by the handler`.

### Finding Description
`WebhooksController` verifies the webhook signature using only the organization/owner named in the payload, not the specific repository: `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`. [4](#0-3) 

By contrast, every other webhook handler in `app/models/shipit/webhooks/handlers/**` that touches persisted state resolves the target `Repository`/`Stack` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before performing any write, e.g. `Handler#stacks`, and all `PullRequest::*Handler` classes. [5](#0-4)  `StatusHandler` is the exception: it looks up the target purely by commit SHA, globally, across every stack/repository tracked by the Shipit instance:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`Commit#create_status_from_github!` records a `Status` used to compute `Commit#status`, `Commit#success?`/`blocked?`/`deployable?`, which directly gates deploy eligibility for the owning stack: `deployable?` returns true only if `stack.ignore_ci? || (success? && !blocked?)`. [6](#0-5) 

Because a git commit's SHA-1 is a deterministic hash of its tree, parent(s), author/committer, timestamps, and message, an attacker who can observe a target commit's metadata (trivial for a public repository, or for a private repository the attacker was previously granted read access to, e.g. via a fork) can reconstruct a byte-identical commit object and push it into a repository they legitimately control that is *also* onboarded to the same Shipit instance (e.g., because both the victim's and the attacker's repos belong to the same GitHub organization, or the instance hosts multiple orgs under one Shipit deployment). When GitHub fires a genuine, correctly signed `status` webhook for the attacker's own repository/commit, `WebhooksController#verify_signature` passes (it is genuinely signed for the attacker's own org/repo). `StatusHandler` then updates the status of **every** `Commit` row sharing that SHA — including the victim's `Commit` belonging to an entirely different `Stack`/`Repository` that the attacker has no write access to. This lets the attacker inject a fabricated "success" status (with an arbitrary `context`, matching a `required_statuses` entry) onto a victim commit, satisfying `Commit#deployable?` for a stack the attacker cannot otherwise write to.

This is the same class of bug as the report's TVL issue: a value used to gate a privileged decision (deploy eligibility) is updated through a channel whose authorization binding (org/repo that signed the request) does not match the entity actually mutated (an unrelated repository's tracked commit). The webhook's authenticated organization ≠ the repository whose `Commit`/deploy-gating state gets written.

### Impact Explanation
This allows cross-repository state corruption of CI status data that directly feeds into deploy-safety decisions (`Commit#deployable?`, `Stack#continuous_deployment?` triggers via `schedule_continuous_delivery`). An attacker with commit access to any repository tracked in the same Shipit instance can forge required-CI-status success for a commit in a completely different, unrelated repository, and if that stack has continuous deployment enabled, this can trigger an **unauthorized deploy** of the victim's stack — one of the explicitly in-scope High-impact outcomes. [7](#0-6) 

### Likelihood Explanation
The likelihood is moderate: it requires (a) two repositories tracked by the same Shipit instance, at least one of which the attacker can push to, (b) the attacker's ability to reconstruct a byte-identical commit (straightforward for public repositories, or any repository whose commit metadata the attacker can read), and (c) the victim stack relying on a `required_statuses`/`blocking_statuses` check and/or continuous deployment. No privileged Shipit credentials, session, or `ApiClient` token are required — only ordinary GitHub push access to some repository already connected to the instance, which is an unprivileged-attacker path relative to the victim stack.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-only lookups) to the repository identified in the webhook payload, mirroring the pattern already used by `Handler#stacks` / `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
More generally, ensure every webhook handler binds its write target to the same repository entity that `WebhooksController#verify_signature` used to authorize the request, not solely to loosely-unique fields like a commit SHA.

### Proof of Concept
1. Shipit instance tracks `victim-org/victim-repo` (stack A) and `attacker-org/attacker-repo` (stack B), both configured with their own GitHub App webhooks pointed at the same Shipit deployment.
2. Attacker observes (or already has read access to) a commit `C` in `victim-org/victim-repo` that is pending/failing a required CI context, e.g. `ci/required-check`, blocking deploy of stack A.
3. Attacker reconstructs an identical git commit object (same tree, parents, author/committer identities and timestamps, message) locally so it hashes to the same SHA as `C`, and pushes it into `attacker-org/attacker-repo`.
4. Attacker (or their own CI) posts a genuine, correctly-signed GitHub `status` webhook event for `attacker-org/attacker-repo` at that SHA with `state: success`, `context: ci/required-check`.
5. `WebhooksController#verify_signature` validates the signature against `attacker-org`'s webhook secret and succeeds. [4](#0-3) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matches the victim's `Commit` row (stack A) by SHA, and calls `create_status_from_github!`, marking commit `C` as successful for `ci/required-check` in stack A even though the attacker never had write access to `victim-org/victim-repo`. [3](#0-2) 
7. If stack A has continuous deployment enabled or a maintainer triggers a deploy relying on this now-forged status, the deploy proceeds despite the attacker never having contributed to `victim-org/victim-repo`.

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

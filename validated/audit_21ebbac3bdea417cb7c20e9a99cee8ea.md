Confirmed: `StatusHandler#process` in `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` resolves target commits with `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a query scoped only by `sha`, across the entire `commits` table, with no filter on `stack_id`/`repository`. The webhook signature is verified per-organization using `repository_owner` derived from the payload's own `repository.owner.login` (or `organization.login`) field [1](#0-0) , so a valid signature only proves the payload came from *some* organization Shipit trusts — it does not bind the `sha` field to that organization's repository. `create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)` which creates a `Status` row scoped to whichever `commit.stack` happens to own that sha [2](#0-1) [3](#0-2) .

### Title
Cross-repository commit status forgery via unscoped SHA lookup in webhook `status` handler — (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
### Finding Description
The `status` webhook handler only verifies that a payload's HMAC signature matches the `webhook_secret` configured for the organization named in the payload's `repository.owner.login` field [4](#0-3) . That check establishes trust that *an organization* configured in Shipit sent the payload, but the payload's `sha` field is never validated against that same organization/repository. `StatusHandler#process` uses the attacker-controlled `sha` to look up commits globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . Because git commit SHAs are content-addressed, identical commit content (e.g., a shared vendored file, an empty/trivial commit, a cherry-picked or forked commit, or a commit deliberately crafted to be byte-identical) can legitimately exist in more than one repository tracked by the same Shipit instance. An attacker who controls one onboarded repository/organization (with its own legitimate `webhook_secret`) can push a commit whose SHA matches a commit already present in a *different* stack's repository, then send a signed `status` webhook naming that shared SHA with an arbitrary `state`/`context`/`description`. `Status.replicate_from_github!` writes this status keyed by `commit.stack_id` derived from the matched `Commit` record — i.e., the victim stack — not the attacker's own stack [3](#0-2) .

This breaks the equality the engine's trust model depends on: `organization authenticated by webhook signature == repository/stack whose commit status is written`. The signature only proves "some trusted org sent this," while the actual write target is chosen purely from an attacker-supplied `sha` with no ownership check.

### Impact Explanation
A forged `success` status on a required/blocking CI context (`ci.require`/`ci.blocking` in `shipit.yml`) makes a victim's commit `deployable?` true even though real CI never passed, since `deployable?` and `blocked?` are computed purely from `Status`/`CheckRun` records attached to the commit [6](#0-5) . Combined with `continuous_deployment`, this can trigger `schedule_continuous_delivery` and an actual unauthorized deploy of the victim stack, since a `success` status also enqueues `ContinuousDeliveryJob` [7](#0-6) ; conversely a forged `failure`/`error` status can be used to block deploys or the merge queue for a competitor's repository (denial of legitimate deploys). This crosses a repository/organization write boundary the engine is meant to enforce, matching "unauthorized deploy" impact.

### Likelihood Explanation
Exploitation requires: (1) control of at least one repository/organization already onboarded to the target Shipit instance (so the attacker legitimately knows/receives a `webhook_secret` for signing), and (2) getting a commit with an identical SHA to a commit present in the victim stack. Because SHA is a hash of tree+parent+metadata, an attacker cannot choose an arbitrary target SHA, but can achieve collisions deliberately in cooperative/likely scenarios (shared open-source dependency commits, forked repos tracked as separate stacks, cherry-picks across mono/poly-repo setups, or an attacker who is also a legitimate contributor to the victim's repo and can push the exact same tree/commit metadata to their own separate repo). This is a real, if narrower, likelihood than a fully unauthenticated attack, but it is a genuine cross-tenant boundary break with no additional privilege (no `ApiClient` token, no GitHub App key, no session) beyond authoring one onboarded repo.

### Recommendation
Scope the `StatusHandler` lookup to commits belonging to stacks whose repository matches the payload's `repository`/`organization` fields (already used for signature verification), e.g. `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { owner: repository_owner, name: repository_name })`, instead of an unscoped `Commit.where(sha: ...)`. Apply the same repository-scoping check to any other webhook handler that resolves records purely by `sha` without checking `repository_owner`/`repository_name` consistency.

### Proof of Concept
1. Attacker onboards `attacker-org/repo-a` as a Shipit stack and legitimately obtains its `webhook_secret` (e.g. via a classic GitHub webhook they control, or knowledge from initial setup).
2. Victim stack `victim-org/repo-b` has a required/blocking CI context, e.g. `ci/travis`, and a pending commit `C` with sha `abc123...` that the attacker can also reproduce byte-for-byte in `repo-a` (e.g. via a shared vendored commit, submodule commit, or cherry-pick with identical author/committer timestamps and tree), producing the same sha in both repositories.
3. Attacker sends `POST /webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with `attacker-org`'s `webhook_secret`, and body `{"sha":"abc123...","state":"success","context":"ci/travis","repository":{"owner":{"login":"attacker-org"}, ...}}`.
4. `WebhooksController#verify_signature` succeeds because it only checks the signature against `attacker-org`'s secret [4](#0-3) .
5. `StatusHandler#process` finds `Commit` `C` (belonging to `victim-org/repo-b`) via the unscoped `Commit.where(sha: params.sha)` and creates a forged `success` status on it [5](#0-4) , flipping `deployable?` for the victim's commit and, if continuous deployment is enabled, triggering an unauthorized deploy of `victim-org/repo-b`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

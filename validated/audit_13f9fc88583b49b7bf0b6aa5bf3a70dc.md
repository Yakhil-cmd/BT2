### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but downstream handlers act on an independently-read `repository.full_name` (or, for statuses, no repository scoping at all) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Once the signature is accepted, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs, and every handler re-parses the *same raw payload* independently, resolving the target repository via `payload.dig('repository', 'full_name')` (see `Shipit::Webhooks::Handlers::Handler#repository_name`) — a field that is never checked against `repository.owner.login`. `StatusHandler` goes further and doesn't consult the repository at all, matching purely on `Commit.where(sha: params.sha)` across the whole database. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
This is a direct analog of the Sherlock H-1 bug class: a value used to establish trust (`w`/the verified organization) is not the same value that later code acts on (the account whose withdraw request gets mutated / the repository whose data gets mutated). The trust-establishing binding here is:

`verified_organization == repository_owner (payload.repository.owner.login)`

but the binding actually enforced when data is written is:

`affected_repository == payload.repository.full_name` (PushHandler, PullRequest handlers, CheckSuiteHandler) or, worse, `affected_commit == payload.sha` with **no repository check whatsoever** (StatusHandler).

`Shipit` supports multiple GitHub organizations configured in the same instance (`config/secrets.*.yml` documents a `github: { org1: {...webhook_secret...}, org2: {...webhook_secret...} }` shape), each with its own `webhook_secret`. An operator/admin of one configured organization ("Org A") legitimately possesses Org A's `webhook_secret` (they set up the GitHub App). `verify_signature` will accept any payload as long as `HMAC(Org A's secret, raw_body)` matches the `X-Hub-Signature` header and `repository.owner.login == "Org A"` — regardless of what `repository.full_name` or `sha` field the payload actually contains.

Because the handlers never re-check that `full_name`'s owner matches the `repository_owner` used for signature verification, an attacker who is a member/owner of Org A can forge a `push`, `pull_request`, `check_suite`, or `status` webhook whose `repository.owner.login` is `"Org A"` (to pass signature verification) but whose `repository.full_name` (or, for statuses, `sha`) references a stack belonging to a completely different organization ("Org B") also configured on the same Shipit instance.

- `PushHandler` would call `stack.sync_github(expected_head_sha: ...)` on Org B's stacks.
- `PullRequest::ClosedHandler`/`OpenedHandler`/`LabeledHandler` would archive/unarchive/close review stacks belonging to Org B based on `params.repository.full_name`.
- `StatusHandler` is unscoped by repository entirely — it looks up `Commit.where(sha: params.sha)` globally, so an attacker who merely knows a target commit's SHA (visible on GitHub, a public value) can inject a fabricated `success`/`failure` status for that commit into Shipit's own database, regardless of which org the signature was verified against. [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation
The injected `Status` directly feeds `Commit#status` → `Status::Group.compact`, which determines `Commit#deployable?` (`success? && !blocked?`) and is used both by `Stack#trigger_continuous_delivery` (auto-deploys the commit if `continuous_deployment?` is enabled, via `schedule_continuous_delivery`) and by human deploy UIs that gate on required statuses. An attacker who legitimately controls one configured organization's webhook secret can inject a fabricated `success` status against an arbitrary commit SHA belonging to any other organization's stack tracked by the same Shipit instance, satisfying `required_statuses`/blocking-status checks and triggering an **unauthorized deploy** of a commit that never actually passed CI on GitHub. This matches the report's "Critical" impact bucket (unauthorized deploy). [9](#0-8) [10](#0-9) 

### Likelihood Explanation
Likelihood depends on the Shipit instance being configured to serve more than one GitHub organization sharing one deployment (the documented multi-org `secrets.yml` format), and the attacker having legitimate control (as owner/admin) over one of those organizations' GitHub Apps — a low bar compared to compromising credentials of the target organization. Given that `Shipit` explicitly documents and supports this multi-org configuration, this is a realistic deployment topology, and the flaw (checking one field for auth, acting on another) is a straightforward logic gap, not requiring any exotic conditions.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after verifying the signature for `repository_owner`, every handler must re-validate that the repository/organization it is about to act on (`full_name`'s owner, or the resolved `Commit#stack#repository`'s owner) equals the organization whose secret validated the signature, rejecting (422) on mismatch. For `StatusHandler` specifically, scope the `Commit` lookup by the stack's repository owner (matching `repository_owner`) rather than a bare, cross-tenant `sha` lookup.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.yml`: `org-a` (attacker controls this GitHub App and thus knows its `webhook_secret`) and `org-b` (victim organization, stacks tracked in the same Shipit instance).
2. Attacker crafts a `status` event payload:
```json
{
  "sha": "<victim commit sha, e.g. from org-b's public GitHub repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-a" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature using org-a's secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` — matching the victim's commit in `org-b`'s stack — and calls `create_status_from_github!`, inserting a fabricated `success` `Status` row.
6. If that stack has `continuous_deployment: true` or a human relies on the (now falsified) status/required checks, an unauthorized deploy of that commit can be triggered.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
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

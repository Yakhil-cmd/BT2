### Title
Cross-organization commit-status forgery via `StatusHandler` unscoped `sha` lookup enables unauthorized deploy — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC key to check by the `repository.owner.login` field of the payload, but `Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `sha` alone across the *entire* database, with no scoping to the repository/organization whose secret validated the request. This breaks the intended equality "organization whose signature authenticated the request == repository/stack whose data is written," letting the holder of one organization's webhook secret forge GitHub `status` events that flip the CI state of a commit belonging to a completely different stack/organization on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` derives the verification key from the attacker-controlled JSON body itself: [1](#0-0) [2](#0-1) 

This is the documented multi-org configuration where each GitHub organization has its own GitHub App and `webhook_secret`: [3](#0-2) 

Once the signature is accepted, `Webhooks.for_event(event)` dispatches the parsed JSON directly to the handler: [4](#0-3) 

Most handlers (`PushHandler`, `CheckSuiteHandler`, PR handlers) at least scope their side effects through `Repository.from_github_repo_name(payload.dig('repository','full_name'))`: [5](#0-4) 

But `StatusHandler` does not use `stacks`/`repository_name` scoping at all — it queries commits by `sha` globally: [6](#0-5) 

Since `sha` is a 40-hex-char value, and Shipit stacks continuously ingest and display commit SHAs (e.g. via the stack UI, PR pages, deploy pages, or by simply cloning the target public/private repo the attacker doesn't need access to — SHAs are not secret), an attacker who legitimately owns/administers *any* organization configured on the shared Shipit instance (and therefore knows that organization's own `webhook_secret`, since they configured it or received it when the app was created) can:
1. Learn the `sha` of a target commit in a victim stack (commit SHAs are routinely public information, e.g. from GitHub itself, or from the Shipit stack page).
2. POST a forged `status` webhook payload to `/webhooks`, setting `repository.owner.login` to their **own** organization (so `verify_signature` authenticates it with their own known secret) but `sha`, `state`, and `context` referencing the **victim's** commit and the **victim's** required CI check context.
3. `verify_signature` passes because it only checked that the payload was signed by *some* organization's key that the attacker controls — it never confirms that organization actually owns the commit being modified.
4. `StatusHandler#process` finds the victim `Commit` purely by `sha` (regardless of stack/repository) and calls `commit.create_status_from_github!(params)`, writing an attacker-chosen CI state/context onto it.

This directly feeds `Commit#deployable?` and the stack's `required_statuses`/`blocking_statuses` gating logic used before a deploy is allowed: [7](#0-6) [8](#0-7) 

By injecting a fabricated "success" status for a required CI context, the attacker can make a commit that never actually passed CI appear `deployable?`, and because `add_status` triggers `stack.schedule_merges` on success/pending transitions, this can also directly propel an unreviewed/unvetted commit toward being merged or deployed: [9](#0-8) 

This is the same class of bug as the reported `OgvStaking` issue: a field that is *acted upon* (`sha`, effectively "which stack is being written to") is never actually bound to the field that was *cryptographically verified* (`repository.owner.login`). The signature only proves "some org I administer signed this," not "the org that owns this specific commit signed this."

### Impact Explanation
This crosses the "escalation into `Shipit.github_teams` authorization" / "unauthorized deploy" bar explicitly listed as in-scope High/Critical impact: an attacker with legitimate, unprivileged control of one organization's GitHub App/webhook secret on a shared multi-org Shipit instance can forge CI status for arbitrary commits belonging to *other* organizations' stacks, bypassing required-status deploy gating and precipitating an unauthorized deploy/merge of a commit that never passed CI review.

### Likelihood Explanation
Requires only that the target Shipit instance hosts multiple GitHub organizations (an explicitly documented, supported configuration) and that the attacker administers one of those organizations' GitHub Apps (a legitimate, non-privileged-to-Shipit action — they never need a Shipit session, `ApiClient` token, or write access to the victim repository). The victim commit SHA is not secret. No interaction with the victim is required.

### Recommendation
In `WebhooksController#verify_signature` and/or `StatusHandler#process`, bind the verified organization to the actual object being mutated: resolve the target `Repository`/`Stack` via `repository.full_name` (as most other handlers already do) and reject/ignore the status update if the resolved stack's repository owner does not match the organization whose secret validated the signature. At minimum, `StatusHandler` should scope its `Commit` lookup by the repository resolved from `repository.full_name`, not by bare `sha`.

### Proof of Concept
1. Shipit instance configured per `docs/setup.md`'s multi-org example, with `attacker-org` and `victim-org` both onboarded, each with distinct `webhook_secret`s.
2. Attacker administers the `attacker-org` GitHub App and therefore knows `attacker-org`'s `webhook_secret`.
3. Attacker learns/observes the `sha` of a commit in a `victim-org` stack (e.g., visible on the public GitHub repo or the Shipit stack page).
4. Attacker computes `sha256`/`sha1` HMAC over a crafted JSON body using `attacker-org`'s webhook secret:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "required-ci-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
5. POST to `/webhooks` with header `X-Github-Event: status` and the computed `X-Hub-Signature`.
6. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own secret.
7. `StatusHandler#process` executes `Commit.where(sha: params.sha)` — which finds the victim's commit irrespective of organization — and writes the forged "success" status onto it, potentially satisfying `required_statuses` and unblocking deploy/merge for a commit belonging to `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

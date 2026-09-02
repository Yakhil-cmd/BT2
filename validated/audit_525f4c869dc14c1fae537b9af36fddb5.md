## Title
Webhook status events are verified against an attacker‑chosen organization but applied to commits matched only by SHA across all repositories - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
This is the same bug class as the external report: a guard checks the wrong field of an operation instead of the one that actually determines what gets executed. In Shipit, `WebhooksController#verify_signature` selects *which organization's webhook secret* to validate a signature against using an attacker-controlled field of the payload (`repository.owner.login`), while the `status` event handler that actually mutates state never checks organization/repository ownership at all — it matches commits globally by SHA. The binding that should hold ("the organization whose secret authenticated this payload" == "the repository the payload is allowed to write to") is broken.

### Finding Description
`WebhooksController#verify_signature` derives the GitHub App/organization used for HMAC verification directly from the untrusted JSON body, not from any pre-established per-repository/App identity: [1](#0-0) [2](#0-1) 

Because `repository_owner` is read from the body (`repository.owner.login` or `organization.login`), an attacker who controls a GitHub App/organization installation of their own (`OrgAttacker`) knows that organization's `webhook_secret` and can compute a valid HMAC for any payload as long as `repository.owner.login` is set to `OrgAttacker`.

Downstream, `StatusHandler#process` — which handles the GitHub `status` event and is dispatched purely based on `event == 'status'` — never re-checks the repository/organization named in the payload. It finds target `Commit`s by SHA alone, across the entire Shipit installation: [3](#0-2) 

Compare this with other handlers (e.g. `PushHandler`, `Handler#stacks`) which correctly scope lookups through `repository.full_name`: [4](#0-3) 

`StatusHandler` inherits from `Handler` but does not use `stacks`/`repository_name` at all — it bypasses repository scoping entirely, so the `repository.owner.login` value used for signature verification and the actual target of the mutation (any `Commit` row in the database matching a given `sha`) are two independent, uncorrelated fields of the same attacker-supplied JSON body.

`Commit#create_status_from_github!` then applies the forged status and, on success, schedules merges/deploy eligibility: [5](#0-4) 

Those statuses feed directly into merge-queue admission checks: [6](#0-5) 

### Impact Explanation
An attacker who has installed their own GitHub App (or is an org admin of any org known to Shipit’s `secrets.yml`, e.g. via a free/community org) knows that org's `webhook_secret` and can craft a correctly-signed `status` webhook naming `OrgAttacker` as `repository.owner.login`, but with an arbitrary `sha` value copied from a public commit in an unrelated, victim-owned Shipit-tracked repository, plus `state: "success"`. Because `StatusHandler` matches commits by SHA only, this forges a passing CI status on the victim's commit. If that satisfies `required_statuses`/`blocking_statuses` for the victim stack's merge queue, it can let a pull request bypass real CI and be merged (`MergeRequest#merge!`), or unblock an otherwise-gated deploy — an unauthorized merge/deploy performed with the app's own `GITHUB_TOKEN`/installation credentials. This matches the Critical bucket ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitation requires only: (1) knowledge of one GitHub organization's `webhook_secret` configured in Shipit (attacker's own org, if Shipit is multi-tenant, or any org whose secret leaks/is discoverable), and (2) the target commit SHA, which is public information on GitHub. No Shipit session, API token, or write access to the victim repository is needed — this is exactly the unprivileged-attacker, cross-organization/cross-repository class the prompt calls out.

### Recommendation
- **Short term:** In `StatusHandler` (and any other handler that doesn't already scope through `Handler#stacks`), verify the commit belongs to a stack whose `Repository#full_name`/owner matches the `repository` object in the same payload that was used for signature verification, rejecting mismatches.
- **Long term:** Make the organization/repository binding explicit and enforced once, e.g. resolve the repository owner in `verify_signature`, store/pass it through, and require every handler that mutates state (not just `Push`/`PullRequest` handlers) to re-validate that the payload's declared repository matches the record being modified. Add negative test coverage asserting that a `status` webhook naming org A cannot affect commits belonging to a stack under org B.

### Proof of Concept
1. Attacker controls `OrgAttacker`, which is configured in Shipit's `secrets.yml` (or is otherwise a known organization with a leaked/attacker-known `webhook_secret`).
2. Attacker finds a public commit SHA `S` on `victim-org/victim-repo`, tracked by Shipit as a stack with `required_statuses` gating merges.
3. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgAttacker/whatever" }
}
```
signed with `OrgAttacker`'s `webhook_secret` via `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgAttacker")` and validates successfully since the attacker knows that secret. [1](#0-0) 
5. `StatusHandler#process` matches `Commit.where(sha: "S")` regardless of which repository it belongs to and creates a passing status, potentially unblocking the victim's merge queue/deploy gate. [3](#0-2)

### Citations

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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/merge_request.rb (L155-206)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

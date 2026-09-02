### Title
Webhook signature verified against `repository.owner.login`'s org while handlers resolve stacks via `repository.full_name`, allowing cross-org commit mutation - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb, app/models/shipit/webhooks/handlers/check_suite_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature using `payload.dig('repository','owner','login')`, while `Handler#repository_name` (used by `CheckSuiteHandler#stacks`) resolves the target `Repository`/`Stack` using the independent field `payload.dig('repository','full_name')`. Because these two fields are never cross-validated, an attacker who legitimately controls org A's webhook secret can sign a payload whose `repository.full_name` points at a different organization's repository, causing Shipit to run `CheckSuiteHandler#process` against org B's stack and commits.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`organization_that_signed(payload) == organization_owning(Repository.from_github_repo_name(payload['repository']['full_name']))`

Trace:
- `verify_signature` in [1](#0-0)  picks the GitHub App config via `Shipit.github(organization: repository_owner)`, where `repository_owner` is defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .
- After signature verification succeeds, `WebhooksController#create` dispatches the *entire raw JSON payload* to the handler [3](#0-2) .
- `Handler#stacks` and `Handler#repository_name` resolve the target repository from a *different* JSON field, `payload.dig('repository', 'full_name')` [4](#0-3) .
- `CheckSuiteHandler#process` then queries `stacks.where(branch: ...)` and calls `schedule_refresh_check_runs!` on matching commits [5](#0-4) .

Since `repository.owner.login` and `repository.full_name` are both attacker-supplied JSON fields in the same POST body and are read independently with no consistency check, an attacker who owns/administers org A (and therefore legitimately knows org A's configured `webhook_secret` in Shipit) can:
1. Build a `check_suite` JSON payload with `repository.owner.login = "org-A"` and `repository.full_name = "org-B/target-repo"`, plus `check_suite.head_branch` set to a branch tracked by one of org B's Stacks and `check_suite.head_sha` matching a real commit on that stack.
2. Compute the HMAC-SHA1 signature over the raw body using org A's own `webhook_secret` (which the attacker knows because they configured it), and send it as `X-Hub-Signature`.
3. `verify_signature` resolves `Shipit.github(organization: "org-A")`, verifies the signature successfully (it matches, since it was computed with org A's real secret), and the request proceeds.
4. `CheckSuiteHandler#stacks` resolves `Repository.from_github_repo_name("org-b/target-repo")`, unrelated to org A, and finds org B's stacks/commits.
5. `schedule_refresh_check_runs!` is invoked on org B's commit, with no involvement, authentication, or consent from org B.

None of the existing guards prevent this: `verify_signature` only checks that the signature matches *some* configured org's secret; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `CheckSuiteHandler.params` validates presence/type of `head_sha`/`head_branch` but not any relationship between `repository.owner.login` and `repository.full_name`; `Repository.from_github_repo_name` merely does a case-insensitive lookup with no ownership check tying it back to the verified signing organization.

### Impact Explanation
A payload authenticated for one organization (org A) causes state mutation (`schedule_refresh_check_runs!` → enqueuing `RefreshCheckRunsJob`) against a commit belonging to a completely different organization's stack (org B), without org B ever authenticating or being involved. This matches the Critical category explicitly listed in the rules: "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any repository/stack whose full name the attacker knows, is not limited to a single target, and works across tenant boundaries — any org onboarded to the same Shipit instance with a configured webhook secret can forge events that mutate any other onboarded org's commit/check-run state.

### Likelihood Explanation
Preconditions are modest and match the described attacker: the attacker must own/administer org A, which must have a `webhook_secret` configured in Shipit (a normal onboarding step, not privileged access to Shipit internals), and org B must have an existing Stack tracking a known branch with a known commit SHA (both discoverable via public GitHub metadata). No Shipit session, API token, or GitHub secret belonging to org B is required. Constructing and signing the payload is trivial (standard HMAC-SHA1 over JSON bytes) and repeatable at will.

### Recommendation
In `Handler#repository_name` (or in `WebhooksController#verify_signature`), enforce that the organization used to resolve the signature (`payload.dig('repository','owner','login')`) matches the owner segment of `payload.dig('repository','full_name')` before proceeding; reject the request (e.g., `head(422)`) on mismatch. Alternatively, derive the repository/organization used for both signature verification and stack resolution from a single, consistently-parsed field.

### Proof of Concept
Add a minitest to `test/controllers/webhooks_controller_test.rb` (or a new handler test) that:
1. Configures two orgs in `Shipit.github_apps`/secrets fixtures: `org-a` with secret `SECRET_A`, and `org-b` (no relation to A).
2. Creates a `Shipit::Repository` for `org-b/target-repo` with a `Shipit::Stack` tracking `branch: "main"`, and a `Shipit::Commit` with a known `sha`.
3. Builds a `check_suite` JSON body with:
   - `repository.owner.login = "org-a"`
   - `repository.full_name = "org-b/target-repo"`
   - `check_suite.head_branch = "main"`, `check_suite.head_sha = <the known sha>`
4. Signs the raw body with `SECRET_A` and sets it as `X-Hub-Signature`.
5. Asserts, before the request: `commit.stub(:schedule_refresh_check_runs!) { raise "should not be called without org-b auth" }` is not yet triggered (baseline).
6. POSTs to `/webhooks` with `X-Github-Event: check_suite`.
7. Asserts the response is not `422` (i.e., signature verification for org-a succeeded).
8. Asserts `schedule_refresh_check_runs!` was invoked on the org-b commit (e.g., via `Commit.any_instance.expects(:schedule_refresh_check_runs!)` or checking that `RefreshCheckRunsJob` was enqueued for that commit) — demonstrating the equality `organization_that_signed == organization_owning(target_stack)` is false (`org-a != org-b`) yet the mutation still occurred.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

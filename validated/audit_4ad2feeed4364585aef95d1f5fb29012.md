### Title
`status` webhook signature check binds to attacker-chosen `repository.owner.login`, but `StatusHandler` mutates by SHA with zero repository/stack scoping - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the signing `GitHubApp` using `repository.owner.login` (or `organization.login`), an attacker-controlled field, and if that chosen org has no `webhook_secret` configured, `verify_webhook_signature` returns `true` unconditionally. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no reference to `repository.full_name`, `repository_owner`, or any stack scoping at all, so any commit sha in the entire database can receive a forged status regardless of which org "authenticated" the request.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`org_that_authenticates_request (Shipit.github(organization: repository_owner))` should equal `org_that_owns_the_mutated_resource (the actual GitHub org/repo owning the Commit/Stack whose sha is being written)`.

Trace:
1. `repository_owner` is read straight from attacker-controlled JSON: `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) .
2. `verify_signature` uses that value to pick which `GitHubApp` instance (and thus which `webhook_secret`) validates the signature: `github_app = Shipit.github(organization: repository_owner)` [2](#0-1) .
3. `verify_webhook_signature` trivially returns `true` if that org's config has no `webhook_secret` set: `return true unless webhook_secret` [3](#0-2) . Example multi-org configs in this repo explicitly show `webhook_secret: # nil` as a normal/documented value for an org [4](#0-3) , and the docs show the same top-level fallback (`return true unless webhook_secret`) applies per-org under "Using Multiple Github Applications" [5](#0-4) .
4. Once past `verify_signature`, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) . Note the handler's params schema never requires or reads `repository` at all [7](#0-6) .
5. `Commit.where(sha:)` is a bare, unscoped query — `Commit` belongs to a `Stack` [8](#0-7)  but the handler never filters by `stack_id`, `repository`, or the payload's `repository.full_name`/owner. `create_status_from_github!` then writes a `Status` row scoped only to `commit.stack_id`, derived from whatever stack the matched commit happens to belong to [9](#0-8) , and `Status.replicate_from_github!` persists it [10](#0-9) .
6. Downstream, a new `Status` triggers `schedule_continuous_delivery` on the commit [11](#0-10) [12](#0-11) , and if the target stack has `continuous_deployment: true` and is otherwise deployable, `ContinuousDeliveryJob` triggers a real deploy [13](#0-12) , as demonstrated in existing tests that show a `success` status alone causes `Deploy.count` to increase [14](#0-13) .

Root cause: the signature-verification org selection and the status-mutation target are two independent, unrelated pieces of attacker-supplied/database state — `repository_owner` (step 1) has no relationship to which `Commit`/`Stack` gets mutated (step 4-5), because `StatusHandler` doesn't consult the `repository` object whatsoever. The `review_stacks_enabled` flag is irrelevant to this specific handler: that flag only gates PR-provisioning handlers (`OpenedHandler#provision?`, `LabeledHandler`, `UnlabeledHandler`) [15](#0-14) , not `StatusHandler`, so the "provision precedence bug" premise in the question does not connect to this handler's code path — I found no code in `StatusHandler` or `Commit`/`Status` that references `review_stacks_enabled` at all.

Existing guards and why they don't stop this: `verify_signature` (per-org secret check) only proves the *sender knows a secret for the org named in the payload* — it says nothing about the org that actually owns the commit being mutated, since `Commit.where(sha:)` never joins back to a repository/org. There is no `ExplicitParameters` requirement for `repository` in `StatusHandler`, and no model-level check tying a `Status` write to the repository that authenticated the webhook.

### Impact Explanation
An attacker who knows (or can predict/leak) a target commit's SHA can forge a `status` webhook, choose any org in the multi-org config lacking a `webhook_secret` to trivially pass `verify_signature`, and have `StatusHandler` write a fabricated CI status (e.g., `success`) onto a commit belonging to a completely different, victim-owned `Stack`. This is a cross-tenant write: "a payload for one repository mutating another's stack, commit" — matching the Critical impact category. If the victim stack has `continuous_deployment: true`, this can trigger an unauthorized deploy via `ContinuousDeliveryJob`. This is repeatable against any commit sha in the system, for any number of stacks configured under multi-org Shipit deployments, as long as at least one configured org has no `webhook_secret`.

### Likelihood Explanation
Preconditions: Shipit must be configured with the multi-org github config schema, and at least one configured org must have `webhook_secret` unset/blank (shown as a normal documented configuration in this repo's own example secrets files). The attacker needs to know a target commit SHA (commit shas are typically public on GitHub) and craft a `status` webhook payload with `repository.owner.login` set to the no-secret org. This requires no GitHub App private key, no `webhook_secret`, and no Shipit session — only knowledge of Shipit's org-naming scheme and a target SHA. Feasibility is high in any deployment using the documented multi-org pattern with a permissive/no-secret org present.

### Recommendation
`StatusHandler` (and other handlers relying on `Commit.where(sha:)`/similar cross-stack lookups) should scope commit/status mutations to the repository that authenticated the webhook — resolve the target `Stack`/`Repository` from `params.repository.full_name`, verify it belongs to the same org as `repository_owner` used for signature verification, and constrain the `Commit` lookup to that stack. Additionally, `verify_webhook_signature`'s `return true unless webhook_secret` fallback should not silently authorize; if used intentionally for orgs with no secret, that org's identity must not be allowed to satisfy signature checks for otherwise-secured orgs' repositories.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, using existing fixtures):
1. Configure two orgs via `secrets_double_github_app.yml`-style fixture: `OrgOne` with a `webhook_secret` set, `OrgTwo` with `webhook_secret: nil`.
2. Take `commit = shipit_commits(:first)` belonging to a stack owned by `OrgOne`, with `stack.update!(continuous_deployment: true)`.
3. POST a `status` webhook: `X-Github-Event: status`, body `{ "sha" => commit.sha, "state" => "success", "repository" => { "owner" => { "login" => "OrgTwo" }, "full_name" => "OrgTwo/unrelated-repo" } }`, with an invalid/garbage `X-Hub-Signature`.
4. Assert `assert_response :ok` (signature check passes because `OrgTwo` has no secret) — equality-under-test: `Shipit.github(organization: 'OrgTwo').verify_webhook_signature(...)` returns `true` even though the actual owning org is `OrgOne`.
5. Assert `commit.statuses.last.state == 'success'` — proving a status was written for `OrgOne`'s commit despite the request being "authenticated" via `OrgTwo`.
6. Assert `assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack])` to show unauthorized deploy triggering.

If either assertion in step 4/5 fails (e.g., the app already scopes `Commit` lookups by the authenticating org), the vulnerability does not hold; based on the code read, no such scoping exists in `StatusHandler`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

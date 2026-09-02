### Title
Cross-organization CI status forgery via unscoped `StatusHandler` webhook processing - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook handler resolves target commits globally by SHA, independent of the repository/organization that authenticated the request via HMAC signature. Any onboarded GitHub organization admin (who legitimately knows only their own org's `webhook_secret`) can forge a signed `status` webhook payload claiming their own org as the sender while targeting a commit SHA belonging to a completely different organization's stack, forging a passing CI status that influences deploy safety gating for a repository they have no access to.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC against using `repository_owner`, itself read straight out of the attacker-controlled JSON payload body: [1](#0-0) [2](#0-1) 

Once the signature is accepted for whichever organization the attacker names in `repository.owner.login`, the raw parsed JSON is dispatched to handlers unmodified: [3](#0-2) 

Critically, `StatusHandler#process` never scopes by repository at all — it looks up commits globally by SHA across the entire database: [4](#0-3) 

Unlike other handlers (e.g. `PushHandler`, `Handler#stacks`) which resolve the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')`, `StatusHandler` performs no such binding: [5](#0-4) [6](#0-5) 

This breaks the binding: **organization that authenticated the webhook (used to pick `webhook_secret`) ≠ repository/stack whose commit is written**. Every `Commit` record in the multi-tenant instance sharing SHA prefixes/values is fair game to whichever org's secret was used, because `Commit.where(sha: params.sha)` is not filtered by `stack_id`/`repository_id`.

The forged status is persisted via `Commit#create_status_from_github!`, which directly feeds into deploy-safety evaluation: [7](#0-6) [8](#0-7) [9](#0-8) 

`deployable?` and `MergeRequest#all_status_checks_passed?` rely on this status, and marking a commit as `success` can unlock deploys or auto-merges for stacks the attacker never had rights to touch: [10](#0-9) 

The multi-org configuration this engine supports explicitly gives each onboarded organization its own `webhook_secret`, so an attacker only needs to be a legitimate, unprivileged admin of any one onboarded org to know one valid secret: [11](#0-10) 

### Impact Explanation
Forging a passing CI status on an arbitrary commit in a repository/stack the attacker does not control can bypass required-status deploy gating (`Commit#deployable?`) and merge-queue gating (`MergeRequest#all_status_checks_passed?`), enabling an unauthorized deploy or merge to proceed on another organization's stack — a cross-repository write and unauthorized-deploy scenario matching the "High/Critical" impact bar (unauthorized deploy / cross-repository writes).

### Likelihood Explanation
Any organization already onboarded to the multi-tenant Shipit instance (a normal, unprivileged, expected state for organizations using shared Shipit deployments) possesses a valid `webhook_secret` for itself. Crafting the payload only requires knowledge of a target commit SHA in another org's stack (visible via the public Shipit UI/API, git history, or GitHub itself) — no privileged Shipit account, ApiClient token, or GitHub write access to the victim repository is required.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records without going through `Handler#stacks`) to only operate on commits belonging to the repository named in `payload.dig('repository', 'full_name')`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(repository_name)`. Additionally, cross-check that `repository_owner` used for signature verification matches the repository actually referenced in the payload before dispatching to handlers, rejecting any mismatch.

### Proof of Concept
1. Attacker is the legitimate admin of GitHub org `attacker-org`, onboarded to the shared Shipit instance with its own `webhook_secret` (`S_A`) per the multi-org config format.
2. Attacker finds a commit `sha=deadbeef...` belonging to `victim-org/critical-repo`'s stack (visible via public Shipit stack page).
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` using their own known secret `S_A`.
5. POST to `/github/webhooks` with `X-Github-Event: status`. `verify_signature` picks `Shipit.github(organization: 'attacker-org')` and validates successfully against `S_A`.
6. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')` and finds the commit belonging to `victim-org/critical-repo`, calling `create_status_from_github!`, marking it `success` regardless of real CI state — potentially unlocking deploy/merge for a stack the attacker has no access to.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
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

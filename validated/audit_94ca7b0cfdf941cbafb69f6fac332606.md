### Title
`Shipit::Webhooks::Handlers::Handler#stacks` resolves target repository from an unauthenticated field, letting a webhook authenticated for one GitHub org mutate another org's stacks - ([File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` to check against `request.raw_post` using `payload.dig('repository','owner','login')`, but `Handler#stacks` resolves the actual `Repository`/`Stack` to mutate using a completely different field, `payload.dig('repository','full_name')`. No code anywhere compares these two values, so a single crafted JSON body can authenticate as org A while acting on org B's stack.

### Finding Description
Binding claimed: `authenticated_org(payload) == owning_org(resolved_repository)`.

- `authenticated_org(payload)` = `WebhooksController#repository_owner` = `params.dig('repository','owner','login') || params.dig('organization','login')`, used only to pick which `GitHubApp` config (and its `webhook_secret`) is used to verify `X-Hub-Signature` against `request.raw_post`. [1](#0-0) [2](#0-1) 

- `owning_org(resolved_repository)` is derived inside `Handler#stacks`/`#repository_name` from `payload.dig('repository','full_name')`, an entirely independent JSON field in the same body: [3](#0-2) 

Because GitHub's own webhook payloads always keep `repository.owner.login` and `repository.full_name` consistent, this divergence normally cannot occur for genuine deliveries. But `POST /webhooks` accepts any raw HTTP body from any internet client — it is not restricted to actual GitHub delivery — so an attacker can submit a JSON body where these two fields disagree.

The remaining gate is `verify_webhook_signature`, which trivially returns `true` when the selected org's `webhook_secret` is blank: [4](#0-3) 
`webhook_secret` is explicitly documented as optional ("If you've set a webhook secret during the App creation, you should copy it here"), and the shipped test/dummy configuration leaves it `nil` by default, confirming this is a supported deployment shape, not a contrived edge case.

Exploit: attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{"repository": {"owner": {"login": "org-with-no-secret"}, "full_name": "victim-org/victim-repo"},
 "ref": "refs/heads/main", "after": "<attacker-chosen-sha>"}
```
`verify_signature` resolves `Shipit.github(organization: "org-with-no-secret")`; since that org has no `webhook_secret` configured, `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header. The request is then dispatched: [5](#0-4) 
to `PushHandler.call(params)`, whose `#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` — a repository never authenticated by this request — and mutates its stacks: [6](#0-5) 

`stack.sync_github(expected_head_sha:)` enqueues `GithubSyncJob`, which appends real commits fetched via the victim stack's own GitHub credentials and, on eventual CI success on those commits, can lead to `Stack#schedule_continuous_delivery` / `ContinuousDeliveryJob.perform_later(stack)` firing for a stack whose owning org never authorized the triggering bytes. [7](#0-6) [8](#0-7) 

None of the existing guards close this gap: `verify_signature` only picks a secret by `repository_owner`/`organization.login` and never re-checks it against `repository.full_name`; `drop_unhandled_event` and `check_if_ping` are unrelated; the `ExplicitParameters` schema for `PushHandler` only requires `ref` and `after`, not that `repository.owner.login == repository.full_name.split('/').first`; and `Repository#from_github_repo_name` performs a plain lookup with no cross-check against the authenticating org. [9](#0-8) [10](#0-9) 

### Impact Explanation
An attacker who has never interacted with the victim org can force Shipit to treat the victim's `Stack` as if it received a legitimate webhook: enqueue `GithubSyncJob` (fetching new commits and updating `cached_deploy_spec`) and, contingent on the stack's `continuous_deployment` flag and normal CI success on that repository, cause `ContinuousDeliveryJob#perform` to trigger an unscheduled deploy. This is a record/action performed against a repository/stack that never authenticated the request — matching the "payload for one repository mutating another's stack" / "unauthorized deploy" critical category. It is repeatable against any stack in the install and is not limited to a single victim; any org/repo pair can be targeted as long as the attacker names an org (in `repository.owner.login`) whose Shipit-side `webhook_secret` is unset.

### Likelihood Explanation
Exploitability is conditioned on at least one org configured in Shipit having no `webhook_secret` set (or, more generally, whichever org an attacker can name for `repository.owner.login`). This is not a hardening failure invented for the exploit — the setup docs present `webhook_secret` as optional, and the shipped default/test configuration ships with `webhook_secret: nil`. Given that, the attack requires zero secrets, zero sessions, and a single crafted HTTP POST, making it low-cost and highly repeatable. Even without a secret-less org, the underlying binding gap (auth org vs. resolved org are different, uncompared fields) is a genuine defect independent of this specific bypass.

### Recommendation
In `Handler#stacks`/`#repository_name`, cross-validate that the repository resolved from `payload.dig('repository','full_name')` belongs to the same org used by `WebhooksController#verify_signature` (e.g., pass the authenticated org into the handler and assert `resolved_repository.owner == authenticated_org` before returning any stacks), and require `webhook_secret` to be present for every configured org (fail closed instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`).

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/handler_test.rb
test "#stacks resolves repository from full_name, ignoring the org used for signature auth" do
  victim_repo = Shipit::Repository.create!(owner: 'victim-org', name: 'victim-repo')
  victim_stack = Shipit::Stack.create!(repository: victim_repo, branch: 'main')

  payload = {
    'repository' => { 'owner' => { 'login' => 'org-with-no-secret' }, 'full_name' => 'victim-org/victim-repo' },
    'ref' => 'refs/heads/main',
    'after' => 'deadbeef'
  }

  # authenticated_org(payload) as computed by WebhooksController#repository_owner
  authenticated_org = payload.dig('repository', 'owner', 'login')
  # owning_org(resolved_repository) as computed by Handler#repository_name -> Repository.from_github_repo_name
  handler = Shipit::Webhooks::Handlers::PushHandler.new(payload)
  resolved_repo = Shipit::Repository.from_github_repo_name(payload.dig('repository', 'full_name'))

  refute_equal authenticated_org, resolved_repo.owner, "binding is broken: auth org != resolved repo owner"

  assert_includes handler.send(:stacks), victim_stack,
    "Handler#stacks returned a stack belonging to an org that never authenticated this payload"
end
```
This demonstrates, without any live GitHub calls, that `Handler#stacks` returns/operates on a `Stack` whose owning org (`victim-org`) differs from the org (`org-with-no-secret`) that `WebhooksController#verify_signature` used to authenticate the request, with no guard rejecting the mismatch.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-10)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

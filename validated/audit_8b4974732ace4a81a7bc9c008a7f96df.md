### Title
Webhook signing organization is decoupled from the repository actually written by handlers, enabling cross-repository writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The griefing/push-vs-verify mismatch pattern in the external report (an action taken on data that was never actually covered by the trust check that "authorized" it) has a concrete analog in `Shipit::WebhooksController`. The controller selects which GitHub App/organization secret to use for HMAC signature verification based on `repository.owner.login` (or `organization.login`), but the event handlers that actually mutate state resolve the target `Repository`/`Stack` using a *different* field, `repository.full_name`. Nothing enforces that these two values refer to the same repository, so a payload can be signed as one organization while writing into a stack belonging to a different, unrelated repository/organization.

### Finding Description
`WebhooksController#verify_signature` picks the app config to verify against using: [1](#0-0) 
where `repository_owner` is read straight from the attacker-controlled JSON body: [2](#0-1) 

Once the signature is accepted, `create` dispatches the *entire raw payload* to the registered handlers: [3](#0-2) 

Every handler resolves the target repository/stack independently, using `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits this attacker-supplied string on `/` and looks up the row: [5](#0-4) 

So the equality the security boundary depends on is:
`organization used to select the webhook secret (repository.owner.login)` == `organization/repository actually written to (repository.full_name)`

This equality is never checked anywhere in the request path. An attacker who legitimately controls (or has installed) a Shipit-connected GitHub App on **their own** organization "orgA" knows orgA's `webhook_secret`. They can send a webhook whose body sets `repository.owner.login` (and/or `organization.login`) to `"orgA"` — so `verify_signature` selects and validates against orgA's secret and passes — while setting `repository.full_name` to `"orgB/some-repo"`, an unrelated organization/repository already tracked by the same Shipit instance. `PushHandler`, `StatusHandler`, and `CheckSuiteHandler` will then act on `orgB`'s `Stack`/`Repository` because they only look at `full_name`: [6](#0-5) [7](#0-6) 

This matches the required binding class: "an organization that authenticated versus the repository that is written."

### Impact Explanation
This allows cross-repository writes without possessing the target organization's webhook secret: an attacker with only their own org's app/secret can trigger `PushHandler` (queues `GithubSyncJob` to sync a victim stack's commits from a chosen `expected_head_sha`) or `CheckSuiteHandler` (schedules check-run refreshes on a victim stack's commit) against a repository they do not control, purely by mismatching `owner.login` vs `full_name` in the payload body. This is explicitly listed as a High/Critical-tier impact ("cross-repository writes").

### Likelihood Explanation
Requires the attacker to run their own legitimate (or self-created) GitHub App installation registered with this Shipit instance — no privileged Shipit account, `ApiClient` token, or the victim organization's secret is needed, matching the "unprivileged attacker" scope. The only prerequisite is that the target Shipit instance already tracks the victim's repository as a `Stack`, which is the normal multi-tenant configuration this engine is built for (`config/secrets.*.yml` supports multiple orgs, each with distinct webhook secrets, as shown in `config/secrets.development.shopify.yml`).

### Recommendation
In `WebhooksController#verify_signature`/`create`, after determining `repository_owner` and verifying the signature, enforce that every handler's resolved repository (`repository.full_name`) belongs to the same organization/owner used to select the webhook secret — i.e., assert `repository.full_name.split('/').first == repository_owner` (case-insensitively) before dispatching to handlers, and reject (422) otherwise.

### Proof of Concept
1. Attacker installs/owns a Shipit-integrated GitHub App on org `orgA`, and thus knows `orgA`'s `webhook_secret` from `config/secrets.yml`.
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `orgA`'s known `webhook_secret` over this exact body and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` (from `repository_owner`) and successfully verifies the signature against `orgA`'s secret.
5. `create` dispatches params to `PushHandler`, whose `stacks` lookup uses `payload.dig('repository','full_name')` = `"orgB/victim-repo"`, resolving `orgB`'s tracked `Stack`, and calls `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` on a repository the attacker never authenticated for.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

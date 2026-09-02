## Title
Cross-tenant/cross-repository status forgery leading to unauthorized deploy — webhook signature authenticates an organization while `StatusHandler` writes to an unrelated repository's commit ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit's webhook signature check verifies the HMAC of the raw payload against the secret belonging to the *organization named in the payload* (`repository.owner.login`), but the `status` event handler that mutates data never checks that the commit it updates belongs to a stack owned by that same, verified organization. In a Shipit instance configured with multiple GitHub organizations (a documented, supported configuration), an attacker who legitimately controls one onboarded organization's webhook secret can forge a `status` webhook that is valid for *their own* organization, yet references an arbitrary commit SHA belonging to a *different* organization's stack — writing a fabricated CI status and, if that stack has continuous deployment enabled, triggering an unauthorized deploy.

### Finding Description
The webhook signature is verified using an organization selected from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` picks the `GitHubApp` (and its `webhook_secret`) for whichever organization name is embedded in the attacker-controlled JSON body (`repository.owner.login`, or `organization.login`). This is the standard, documented multi-org configuration: [3](#0-2) 

Because the entire request body is attacker-controlled, all that "verification" proves is: *this body was signed by the secret of whichever organization the attacker also named in the body*. It proves nothing about which repository/commit the body's other fields (`sha`, `state`, etc.) actually target.

The `status` webhook handler ignores repository/organization scoping entirely — it looks up commits globally by SHA across the whole Shipit installation and writes a status directly from attacker-supplied fields: [4](#0-3) 

Contrast this with other handlers (`PushHandler`, `PullRequest::*Handler`) which correctly scope to `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before acting: [5](#0-4) [6](#0-5) 

`StatusHandler` has no such check — it never reads `params.repository` at all, so the "organization whose secret authenticated this request" is completely decoupled from "the stack/commit whose status gets written."

The write itself can trigger a real production side effect: creating a `success` status enables continuous delivery: [7](#0-6) [8](#0-7) 

And there's test coverage proving that a `success` status on a stack with `continuous_deployment: true` immediately enqueues a `Deploy`: [9](#0-8) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository_owner in payload)` == `organization/repository that owns the Stack/Commit actually written by StatusHandler`

Before the attack: only GitHub, holding organization B's real webhook secret, can post a valid status for organization B's commits.
After the attack: an attacker who legitimately possesses organization A's webhook secret (e.g., they are a customer/admin who configured that org's GitHub App on a shared Shipit instance) can forge a signature valid for org A's secret while writing a status onto any commit SHA that happens to exist in org B's stacks, because `StatusHandler` performs a global `Commit.where(sha: ...)` lookup with no ownership check.

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy" boundary explicitly called out as Critical impact. An operator who is a legitimate but unprivileged tenant with respect to other organizations on the same Shipit instance can:
- Inject arbitrary/forged CI status (success/failure/error) onto commits belonging to stacks they do not own.
- Trigger an unauthorized deploy on a victim stack with continuous deployment enabled, by forging a `success` status for a commit SHA that is present (or becomes present, e.g. if it's a well-known open-source commit) in the victim's stack.
- This works purely from attacker-controlled payload content; the HMAC signature does not bind the claimed organization to the SHA/state fields being written.

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub organizations (explicitly documented and supported), and requires the attacker to know a target commit SHA in the victim stack (often knowable — e.g., public repositories, or via information leaked through the Shipit UI/API for other stacks on the same instance). No token, no repository write access to the victim repo, and no privileged Shipit account are required — only ownership of one legitimately configured organization's webhook secret on the same shared instance.

### Recommendation
`StatusHandler` (and any other handler that doesn't already scope through `Handler#stacks`/`Repository.from_github_repo_name`) must verify that the commit(s) being updated belong to a stack whose repository owner matches the organization whose secret authenticated the request (i.e., cross-check `repository_owner`/`params.repository.full_name` against the resolved `Commit#stack#repository` before applying the status), mirroring the pattern already used by `PushHandler` and the `PullRequest` handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org example).
2. As the legitimate owner/admin of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret`.
3. Identify a commit SHA `S` that exists in a stack belonging to `OrgB` (e.g., visible in Shipit's public deploy pages, or a well-known upstream commit).
4. Craft a JSON body:
   ```json
   {"sha": "S", "state": "success", "context": "ci/forged", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/some-repo"}}
   ```
5. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
6. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and successfully verifies the signature (using the correctly-known `OrgA` secret) — request passes.
7. `StatusHandler#process` runs `Commit.where(sha: "S")`, finds the commit in `OrgB`'s stack (unrelated to `OrgA`), and calls `create_status_from_github!`, creating a `success` `Status` on it.
8. If that `OrgB` stack has `continuous_deployment: true`, `schedule_continuous_delivery` fires and a `Deploy` is enqueued for `OrgB`'s stack — an unauthorized deploy triggered entirely by `OrgA`'s credentials.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/status.rb (L16-20)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

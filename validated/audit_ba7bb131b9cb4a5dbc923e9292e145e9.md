### Title
Webhook Organization-Selection Bypass Allows Unauthenticated Forgery of CI/Push Events on Any Stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against using an attacker-controlled, *unverified* field (`repository.owner.login`), while the downstream event handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`) act on a completely different set of attacker-controlled fields (`repository.full_name`, `sha`, `check_suite.head_sha`/`head_branch`) that are never cross-checked against the organization used for authentication.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` instance — and therefore the webhook secret used for HMAC verification — based on `repository_owner`, itself read straight from the unsigned-at-parse-time JSON body: [1](#0-0) [2](#0-1) 

Crucially, `GitHubApp#verify_webhook_signature` **short-circuits to `true` when no `webhook_secret` is configured for that organization**: [3](#0-2) 

Shipit explicitly supports multi-organization configurations where each org has its own independent `webhook_secret`, and the setup docs mark `webhook_secret` as *optional*: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (either via bypass when the selected organization has no secret, or otherwise), `create` dispatches to handlers that never revisit `repository.owner.login`. Instead they read `params.after`/`params.ref`, `params.sha`, or `params.check_suite.head_sha`/`head_branch` — fields living in the *same* attacker-supplied JSON body but with no binding back to the organization that was used to pass authentication: [6](#0-5) [7](#0-6) [8](#0-7) 

The binding broken is exactly: *the organization that authenticated the request* (`repository.owner.login`, checked against a secret that may be nil) **≠** *the repository/stack whose state is actually mutated* (via `stacks`/`Commit.where(sha:)` lookups derived from unrelated body fields). Because these two are never cross-validated, an attacker only needs to find (or cause) one configured organization with no `webhook_secret` set — a documented, supported, optional configuration — to unconditionally pass `verify_signature`, and can then aim the payload's action fields (`sha`, `ref`/`after`, `check_suite.*`) at any Stack/Commit tracked by the Shipit instance, including ones belonging to organizations that *do* have a real secret configured.

### Impact Explanation
`StatusHandler#process` calls `commit.create_status_from_github!`, which can flip a commit's state to `success`: [9](#0-8) 
and this is wired to trigger automatic deploys when `continuous_deployment: true`, as demonstrated in the test suite behavior for CD triggering on success statuses: [10](#0-9) 

This lets an unauthenticated network attacker forge a fake CI-success status to trigger an **unauthorized deploy** on any stack tracked by the instance, or forge `push`/`check_suite` events to force resyncs and check-run refreshes on arbitrary repositories — all without any Shipit session, `ApiClient` token, or knowledge of the target organization's real `webhook_secret`.

### Likelihood Explanation
Likelihood depends on at least one configured organization lacking a `webhook_secret` (explicitly optional and common in early/simple setups, and demonstrated by the `secrets.development.example.yml` template shipping with `webhook_secret: # nil`): [11](#0-10) 
Given this is a documented default/example, and the design never re-validates the acting-organization against the authenticating-organization, exploitation requires no privileged credential, only network access to `/webhooks`.

### Recommendation
After selecting the `GitHubApp`/secret by `repository_owner` and verifying the signature, the handlers must verify that the repository/stack they are about to mutate actually belongs to that same, verified organization (e.g., compare `params.dig('repository','full_name')`'s owner segment against `repository_owner`, and reject on mismatch) rather than trusting the "resource identifying" fields unconditionally once any signature check (including a vacuous "no secret configured" pass) succeeds.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `orgA` (no `webhook_secret`) and `orgB` (a real `webhook_secret`, tracking a stack with `continuous_deployment: true`).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/whatever"},
  "sha": "<sha of a commit on orgB's protected stack>",
  "state": "success",
  "context": "ci/forged"
}
```
No `X-Hub-Signature` needed to pass, or an arbitrary/omitted value, because `verify_webhook_signature` for `orgA` returns `true` unconditionally (no secret configured).
3. `WebhooksController#verify_signature` resolves `repository_owner` to `orgA`, verification passes; `StatusHandler#process` then runs `Commit.where(sha: params.sha)` — matching the commit on `orgB`'s stack — and calls `create_status_from_github!`, flipping the commit's status and potentially triggering `ContinuousDeliveryJob`, i.e., an unauthorized deploy on `orgB`'s protected stack.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-25)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L6-18)
```ruby
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

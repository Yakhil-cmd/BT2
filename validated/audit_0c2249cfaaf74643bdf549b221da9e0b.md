### Title
Webhook signature is validated against the payload's `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, letting one onboarded organization forge events for another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to use for HMAC verification based on `repository_owner` (`params.dig('repository','owner','login')`, falling back to `organization.login`), but the handlers that actually mutate state (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc., via `Handler#repository_name` / `Handler#stacks`) select the target repository/stack using the independent `repository.full_name` field of the same attacker-controlled JSON body. Nothing enforces that `repository.owner.login` is a prefix of `repository.full_name`, so a party that legitimately knows one onboarded organization's `webhook_secret` can sign a payload whose `repository.owner.login` matches their own org (passing signature verification) while `repository.full_name` points at a stack belonging to a completely different onboarded organization.

### Finding Description
Verification and authorization operate on two different fields of the same untrusted JSON body:

- Signature verification (authenticates “who signed this”): [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `GithubApp`/webhook secret configured for that organization (Shipit supports multiple organizations, each with its own `webhook_secret`, e.g. `somegithuborg` / `someothergithuborg`): [3](#0-2) 

- Target-repository resolution (authorizes “what this event acts on”): [4](#0-3) 

`repository_name` reads `payload.dig('repository', 'full_name')` — a completely separate JSON field from the one used to pick the verifying secret. `Handler#stacks` then resolves and mutates real `Stack`/`Commit` records for whatever `full_name` was supplied: [5](#0-4) [6](#0-5) 

Because GitHub itself always sends internally-consistent payloads where `repository.owner.login` and `repository.full_name` refer to the same repository, this inconsistency is never observed in normal operation and is not covered by any test that cross-checks the two fields — the existing test suite only checks that the signature is valid or invalid, never that the signing org matches the acted-upon repository: [7](#0-6) 

An attacker who legitimately administers (and thus knows the `webhook_secret` of) *any* organization onboarded to this multi-tenant Shipit instance can POST directly to `/webhooks` with:
```json
{ "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" }, "sha": "...", "state": "success", ... }
```
signed with `attacker-org`'s own webhook secret. `verify_signature` resolves and validates against `attacker-org`'s `GithubApp`, succeeds, and the event is then dispatched with `repository.full_name = "victim-org/victim-repo"` to the handler, which looks up and mutates `victim-org`'s `Stack`/`Commit` records that the attacker has no authorization over.

### Impact Explanation
This breaks the trust binding: `organization authenticated by verify_signature == organization whose repository is written by the handler`. Concretely, using the `status` event and `StatusHandler`, an attacker can forge a `success` CI status for an arbitrary commit SHA on a victim organization's tracked stack: [8](#0-7) 

`create_status_from_github!` feeds into `add_status`, which — when the new status becomes `success` — calls `stack.schedule_merges` and can trigger `ContinuousDeliveryJob` for continuously-deployed stacks: [9](#0-8) [10](#0-9) [11](#0-10) 

That means an attacker with signing capability for one org's webhook secret can make a commit in an unrelated, victim organization's stack appear `deployable?` (bypassing real CI results) and trigger an automatic merge/deploy via continuous delivery — an unauthorized deploy driven by a forged commit status. `PushHandler`/`CheckSuiteHandler` similarly let the attacker force `GithubSyncJob`/`RefreshCheckRunsJob` to run against a victim's stack using Shipit's own GitHub credentials for that victim org.

### Likelihood Explanation
Requires the attacker to be a legitimate administrator (not a Shipit user, not needing repository write access or a Shipit session/API token) of *any one* organization already onboarded to the same multi-tenant Shipit instance — a scenario explicitly supported and documented by the engine's own multi-org config format. The attacker only needs to know the `webhook_secret` of their own organization (which they set themselves per `docs/setup.md`) and be able to send an HTTP POST to the public `/webhooks` endpoint; there is no rate limiting or extra authorization layer involved.

### Recommendation
In `WebhooksController#verify_signature`, after successful signature verification, additionally assert that the `repository.owner.login` (or `organization.login`) used to select the verifying `GithubApp` matches the owner segment of `repository.full_name` (and any other repository identifiers) in the same payload before dispatching to handlers. Reject the request (422) on mismatch.

### Proof of Concept
1. Onboard two organizations on the same Shipit instance: `attacker-org` (attacker is admin, knows its `webhook_secret`) and `victim-org` (has a tracked `Stack` with the repo `victim-org/victim-repo`).
2. Attacker computes `sha256=<hmac>` over a crafted JSON body using `attacker-org`'s `webhook_secret`:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha256=<hmac>`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates the signature successfully (it was signed with that org's real secret).
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which uses `full_name = "victim-org/victim-repo"` to find `victim-org`'s commit and records a forged `success` status, potentially triggering `stack.schedule_merges`/continuous deployment for `victim-org`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
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
```

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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

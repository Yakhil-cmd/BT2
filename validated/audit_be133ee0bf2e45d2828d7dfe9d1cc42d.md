### Title
Webhook signature is verified against the organization in `repository.owner.login`, but event handlers act on the repository named in `repository.full_name` — allowing cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the `X-Hub-Signature` against using the organization derived from the request body itself (`repository.owner.login`, or `organization.login` as fallback), while every event `Handler` (push, status, check_suite, pull_request) resolves which `Repository`/`Stack` to mutate using a **different** field of the same unauthenticated-at-that-point body: `repository.full_name`. These two fields are never cross-checked, so a signature that is valid for organization A can be replayed with a payload whose `repository.full_name` points at organization B's repository.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 
where `repository_owner` comes straight from the JSON payload:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

After this check passes, `create` hands the full, still-attacker-controlled JSON to every registered handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Every base `Handler` (used by `PushHandler`, `StatusHandler`, the `PullRequest::*Handler`s, etc.) resolves the target `Stack`/`Repository` using an entirely different field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`Repository.from_github_repo_name` simply splits this string on `/` to look up owner/name with no relation back to whichever org's secret validated the signature:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [5](#0-4) 

Shipit is explicitly designed to run with multiple independently configured GitHub organizations/Apps, each with its own `webhook_secret` (see `config/secrets.development.shopify.yml` listing `somegithuborg`/`someothergithuborg` each with a distinct `webhook_secret`) [6](#0-5) . An attacker who legitimately controls (or has installed) the GitHub App for organization A therefore learns/receives real, validly-signed webhook deliveries for A, and thus can compute a valid `X-Hub-Signature` for any payload body of their choosing (since the signature is just an HMAC over the raw body using A's secret, which they possess). By setting `repository.owner.login` (or `organization.login`) to `A` (to select A's secret for verification) but `repository.full_name` to `victim-org/victim-repo`, the forged webhook passes signature verification yet is processed by handlers as if it originated from `victim-org/victim-repo`.

This is exactly the pattern flagged in the reference report: a value used for a validity/authorization check (`repository_owner`, which secret to check the signature against) is decoupled from the value actually acted upon (`repository.full_name`, which stack/repository record is mutated), with no invariant enforcing they refer to the same repository.

### Impact Explanation
This breaks the binding "the organization that authenticated" vs. "the repository that is written." Concretely, an attacker with a valid webhook secret for any one org configured in the Shipit instance can forge cross-organization writes against any other tracked stack:
- `StatusHandler` creates a `Status` from arbitrary attacker-supplied `state`/`context`/`description` on any commit `sha` (`Commit.where(sha: params.sha)`) of the victim stack [7](#0-6) , allowing a required-CI-status check (`ci.require`) to be spoofed for a commit that never actually passed CI, undermining the safety gate that governs whether a commit is deployable.
- `PushHandler` can force `stack.sync_github(expected_head_sha: ...)` on a victim's stack it does not own [8](#0-7) .
- `PullRequest::*Handler`s can archive/unarchive victim review stacks based on forged label/PR data resolved via the same `repository.full_name` lookup [9](#0-8) .

These are unauthorized cross-repository writes into stacks belonging to a different GitHub organization than the one whose secret actually authenticated the request, satisfying the "cross-repository writes" / spoofed deploy-safety-gate impact tier.

### Likelihood Explanation
Exploitation requires the attacker to possess a valid `webhook_secret` for at least one organization configured in the target Shipit instance — a realistic scenario for any multi-tenant/multi-org Shipit deployment where the attacker is a legitimate customer/org owner of one of the configured GitHub Apps, but not of the victim org whose repositories they target. No knowledge of the victim org's own webhook secret is required, and no compromise of Shipit or GitHub credentials is needed beyond the attacker's own, already-authorized org.

### Recommendation
After signature verification, re-derive the organization from the same authenticated field used for lookup (`repository.full_name`'s owner segment) and require it to match `repository_owner` used to select the verifying secret, rejecting the webhook otherwise. Alternatively, bind webhook secrets per-repository/installation (not solely per top-level organization name pulled from the unauthenticated payload) and verify that the resolved `Repository`'s configured organization matches the organization whose secret validated the signature before dispatching to handlers.

### Proof of Concept
1. Attacker legitimately installs/owns the Shipit-connected GitHub App for `attacker-org`, and thus knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `status` (or `push`) webhook JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and sends it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and validates successfully using the attacker's own known secret [1](#0-0) .
5. `StatusHandler#process` looks up commits/stacks via `repository.full_name` = `victim-org/victim-repo`, and writes a forged `success` status onto the victim's commit [7](#0-6) , despite the attacker never possessing `victim-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-69)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

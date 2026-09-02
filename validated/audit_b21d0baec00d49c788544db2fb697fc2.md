### Title
Cross-tenant webhook confused deputy: signature check keys on `repository.owner.login` while `PullRequestClosedHandler` resolves the target repo from `repository.full_name`, allowing archival of a victim's `ReviewStack` under a secret-less org's authentication - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) to validate against using `params.dig('repository','owner','login')`, while `PullRequestClosedHandler#repository` resolves the actual target `Shipit::Repository` using `params.repository.full_name`. These two payload fields are never cross-validated, and `GitHubApp#verify_webhook_signature` fails open (`return true unless webhook_secret`) when the resolved org has no `webhook_secret` configured. This lets an attacker who can produce a valid signature for (or target) a secret-less org craft a raw JSON body naming a victim org/repo in `full_name`, causing `PullRequestClosedHandler#process` to call `review_stack.archive!` on the victim's tracked `ReviewStack`.

### Finding Description
Broken binding (before/after should be equal, but are not enforced to be equal):
`org_that_authenticated_webhook = params.dig('repository','owner','login')` (used in `app/controllers/shipit/webhooks_controller.rb:25,59-62` to pick the `GitHubApp`/secret for `verify_webhook_signature`)
should equal
`org_owning_mutated_resource = params.repository.full_name.split('/').first` (used in `app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb:49-53` via `Shipit::Repository.from_github_repo_name`).

Nothing in the controller or the `ExplicitParameters` schema for `ClosedHandler` (`app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb:8-39`, which only requires `repository.full_name` as a String, with no `owner` sub-object at all) ties these two values together. Since the attacker POSTs raw JSON directly to `/webhooks` (no real GitHub relay, no TLS termination assumptions needed), they fully control both `repository.owner.login` and `repository.full_name` independently. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

Root cause in `verify_webhook_signature`: if the resolved org's `webhook_secret` config is blank, the method returns `true` unconditionally, without even checking the supplied signature header. [5](#0-4) 

Exploit flow:
1. Attacker crafts `{"action":"closed","number":<victim_pr_number>,"pull_request":{...},"repository":{"owner":{"login":"secretless-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`.
2. Attacker sets `X-Github-Event: pull_request` and any (or no valid) `X-Hub-Signature`.
3. `verify_signature` resolves `Shipit.github(organization: "secretless-org")`; since that org has no `webhook_secret` configured, `verify_webhook_signature` returns `true` regardless of the signature supplied.
4. `Shipit::Webhooks.for_event('pull_request')` dispatches to `ClosedHandler`, whose `params` schema only validates shape, not organizational consistency.
5. `ClosedHandler#process` looks up `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")` (a real, victim-owned, tracked repository) and calls `review_stack.archive!`, tearing down the victim's `ReviewStack` for that PR/branch. [6](#0-5) 

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type is registered, not the payload contents; `verify_signature` authenticates the *sender org named in the payload's owner field*, not the org whose resources the handler subsequently mutates; the `ExplicitParameters` schema for `ClosedHandler` requires `repository.full_name` as a bare string with no ownership cross-check against `sender`/`repository.owner`; no model validation in `Repository`/`ReviewStack` re-derives or re-checks the authenticating org against the repository being archived. Note: this specific handler ignores the PR's `merged` field entirely - it archives the review stack purely on `action == "closed"` (`respond_to_pull_request_closed?` at `app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb:61-63`), so the mutation achieved is unauthorized `ReviewStack` teardown/state transition for a victim repo, not literally flipping a `merged` boolean on a `PullRequest` record. [7](#0-6) 

### Impact Explanation
An attacker can force teardown/archival of a victim org's `ReviewStack` (and any associated cleanup/state transitions triggered by `archive!`) without ever possessing that victim org's `webhook_secret`, `secret_key_base`, or any Shipit credential - only knowledge of a *different*, secret-less org's login name configured on the same Shipit instance. This is a cross-tenant mutation: "a payload for one repository mutating another's stack," matching the Critical severity bucket. It is fully repeatable against any tracked repository/PR number as long as one org on the instance lacks a `webhook_secret`, and it works identically for any other webhook-driven handler that resolves its target from `repository.full_name` rather than from the org used for signature verification (the vulnerability is really in the controller's authentication design, and this handler is one concrete, reachable manifestation of it).

### Likelihood Explanation
Preconditions: (1) the Shipit instance must host at least one GitHub org/app configuration with a blank `webhook_secret` (a real, plausible operational gap in multi-tenant self-hosted deployments, not a "secret" the attacker needs to obtain - it's an absence of one); (2) the attacker must know that org's login string, which is typically visible from the Shipit UI/URLs of stacks belonging to that org. No GitHub App private key, `api_clients_secret`, session, or team membership is required. The attacker cost is a single crafted HTTP POST with no signature needed; it is trivially repeatable against arbitrary victim repos/PR numbers on the same instance.

### Recommendation
In `WebhooksController#verify_signature`, derive the authenticating org strictly from a value that also gates the resource being mutated, and reject payloads where `repository.owner.login` does not match the owner segment of `repository.full_name` (or better, derive repository resolution solely from the same owner field validated by signature). Additionally, make `verify_webhook_signature` fail closed (reject) when `webhook_secret` is blank rather than trivially returning `true`, and require every configured org to have a non-blank `webhook_secret` at boot/config-load time.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "cross-org closed payload cannot archive a victim repo's review stack via a secret-less org" do
  # Victim org has a secret configured
  victim_repo = shipit_repositories(:shipit) # owner: "shopify", secret configured
  victim_stack = create_review_stack_for(victim_repo) # fixture helper producing a non-archived ReviewStack

  # Attacker-controlled / secret-less org exists on this instance
  Shipit.stubs(:github).with(organization: "secretless-org").returns(
    Shipit::GitHubApp.new("secretless-org", {}) # no webhook_secret configured
  )

  payload = {
    "action" => "closed",
    "number" => victim_stack.pull_request_number,
    "pull_request" => { ... victim PR fields ..., "merged" => true },
    "repository" => {
      "owner" => { "login" => "secretless-org" }, # used for signature check
      "full_name" => victim_repo.full_name          # used to resolve the mutated resource
    },
    "sender" => { "login" => "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid

  assert_not victim_stack.reload.archived?
  post :create, body: payload, as: :json
  assert_response :ok

  # Binding check: org that authenticated ("secretless-org") != org owning the mutated resource ("shopify")
  assert victim_stack.reload.archived?, "victim ReviewStack was archived by a payload authenticated under an unrelated org"
end
```
Both sides of the equality: `params.dig('repository','owner','login') == "secretless-org"` (authenticating org) vs. `Shipit::Repository.from_github_repo_name(params.repository.full_name).owner == "shopify"` (mutated org) - they diverge, and the victim's `ReviewStack.archived?` flips from `false` to `true`, proving the binding violation and unauthorized state mutation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L61-63)
```ruby
          def respond_to_pull_request_closed?
            params.action == "closed"
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

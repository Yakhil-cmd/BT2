Confirmed. The finding is valid.

### Title
Forged `pull_request` closed webhook via owner/full_name org divergence archives a `ReviewStack` in an unauthenticated repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/organization used to verify `X-Hub-Signature` based on `params.dig('repository', 'owner', 'login')`, while `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler` resolves the repository it mutates from `params.repository.full_name` — a different, independently attacker-controlled field. In a multi-organization Shipit deployment, an attacker can pick a configured org with no `webhook_secret` for the `owner.login` field (making signature verification trivially pass) while pointing `full_name` at a different org's real repository, causing that org's `ReviewStack` to be archived without ever presenting a valid signature for that org.

### Finding Description
The broken binding, stated as an equality that the code fails to enforce:
`organization_used_to_verify_signature (params.repository.owner.login)` MUST equal `organization_that_owns_the_mutated_repository (params.repository.full_name.split('/').first)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and calls `Shipit.github(organization: repository_owner)` to obtain the `GitHubApp` used for verification. [1](#0-0) [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` short-circuits: `return true unless webhook_secret`. If the org resolved in step 1 has no configured `webhook_secret` (the documented/default state for any org, e.g. `webhook_secret: # nil` in the example configs), any signature — even garbage — is accepted. [3](#0-2) 
3. On success, `WebhooksController#create` parses the full JSON body and dispatches it unmodified to every registered handler for the `pull_request` event, including `ClosedHandler`. [4](#0-3) 
4. `ClosedHandler#repository` resolves the target repository from `params.repository.full_name` — not from `owner.login` — via `Shipit::Repository.from_github_repo_name`. [5](#0-4) 
5. `ClosedHandler#review_stack` builds a `ReviewStackAdapter` scoped to that repository's `review_stacks`, looks up the stack by `environment = "pr#{params.number}"`, and `process` calls `review_stack.archive!`, which deprovisions and archives the stack. [6](#0-5) [7](#0-6) [8](#0-7) 

Attacker's exact request: an unauthenticated `POST /webhooks` with `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature`, and a body where `repository.owner.login` = an org configured in Shipit's multi-org `github:` block with no `webhook_secret` (e.g. `OrgTwo` in `test/dummy/config/secrets_double_github_app.yml`, whose `webhook_secret` is `nil`), while `repository.full_name` = `"<VictimOrg>/<victim-repo>"` naming a different, real, secret-protected org's repository, `action: "closed"`, and `number` set to the target PR/environment number.

Why existing guards fail: `drop_unhandled_event` only checks the event type is registered, not organization consistency. `ExplicitParameters` (`params do ... end` in `ClosedHandler`) only validates the shape/types of `repository.full_name`, `number`, etc. — it has no notion of which org's secret verified the request. `Shipit.github(organization:)` only raises `GithubOrganizationUnknown` if the org key doesn't exist at all — it does not compare against the org implied by `full_name`. No code anywhere cross-checks that the verifying org and the mutated repository's org are the same.

### Impact Explanation
An attacker with no `webhook_secret`, no Shipit session, and no API token can archive (deprovision) a `ReviewStack` belonging to an entirely different, secret-protected organization's repository, purely by naming a different, no-secret org in `repository.owner.login`. This is a payload for one organization/repository mutating another organization's stack state — matching the Critical "payload for one repository mutating another's stack" impact category. The attack is repeatable against any PR number/environment for any repository owned by any org configured on the same Shipit instance, as long as at least one org in the multi-org config lacks a `webhook_secret` (a common/default configuration state, not a hardening failure by the victim org). The same divergence pattern (owner.login used for verification vs. full_name used by handlers) exists across other `pull_request` handlers (`opened_handler.rb`, `reopened_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`), widening blast radius to unarchiving/creating stacks and label-driven behavior too, though this question is scoped to `ClosedHandler`.

### Likelihood Explanation
Requires: (1) the Shipit instance uses the multi-organization `github:` config format (documented and supported, e.g. `secrets_double_github_app.yml`), and (2) at least one configured org has no `webhook_secret` set — the default/example value in every shipped config template (`webhook_secret: # nil`). Given that, the attacker cost is a single unauthenticated HTTP POST with a hand-crafted JSON body; no GitHub account, no valid signature, and no reconnaissance beyond knowing (a) any no-secret org name configured on the instance and (b) the target org/repo's `full_name` and a PR number — both of which are public GitHub information. The attack is fully repeatable and requires no timing or race conditions.

### Recommendation
In `WebhooksController#verify_signature`, derive the organization used for verification consistently with what handlers use to resolve the repository (i.e., also derive/validate against `repository.full_name`'s owner segment), and reject the request if `repository.owner.login` and the owner segment of `repository.full_name` diverge. Additionally, every handler that resolves a repository from `params.repository.full_name` should cross-validate that its derived owner matches the `repository.owner.login` that was used for signature verification, or the controller should pass the verified organization down to handlers so they can enforce the invariant.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "cross-org pull_request closed payload archives a stack owned by a different org" do
  # Setup: multi-org config where OrgTwo has no webhook_secret (as in secrets_double_github_app.yml),
  # OrgOne has a real webhook_secret and owns the victim repository/stack.
  Shipit.stubs(:secrets).returns(multi_org_secrets_with_orgtwo_unsecured)

  victim_repo = shipit_repositories(:orgone_repo) # full_name: "OrgOne/rails"
  review_stack = create_review_stack(repository: victim_repo, environment: "pr42")
  assert_not review_stack.archived?

  body = {
    action: "closed",
    number: 42,
    pull_request: { id: 1, number: 42, url: "https://x", title: "t", state: "closed",
                     additions: 1, deletions: 1,
                     head: { sha: "a" * 40, ref: "feature" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    repository: { full_name: "OrgOne/rails", owner: { login: "OrgTwo" } }, # divergence
    sender: { login: "attacker" }
  }.to_json

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = "sha1=deadbeef" # garbage, never validated because OrgTwo has no secret

  post :create, body:, as: :json

  assert_response :ok
  assert review_stack.reload.archived?, "expected victim org's stack to be archived by a payload verified under a different org's (no-secret) identity"
end
```
Equality checked: `params.dig('repository','owner','login')` ("OrgTwo", used to select the `GitHubApp` in `verify_signature`) vs. the owner implied by `params.repository.full_name` ("OrgOne", used by `ClosedHandler#repository` and thus `review_stack.archive!`). The test demonstrates these differ and the request is still accepted and processed. [1](#0-0) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
          end
```

### Title
Cross-tenant webhook forgery via `repository.owner.login`/`repository.full_name` mismatch — signature verified against attacker's org but handlers mutate the repository named in `full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify the HMAC signature using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` in the same attacker-supplied JSON body. Every downstream event handler, however, resolves the actual `Shipit::Repository` to mutate from a *different* field in that same body, `params.repository.full_name`. Because nothing cross-checks that these two fields agree, an attacker who legitimately owns one Shipit-configured GitHub organization can sign a payload with their own `webhook_secret` while setting `repository.full_name` to point at a repository belonging to an entirely different, unrelated organization.

### Finding Description
The intended binding is:
`organization_whose_secret_verified_signature (repository.owner.login) == organization_owning_the_repository_the_handler_mutates (owner segment of repository.full_name)`

Trace:
- `verify_signature` picks the app config via `repository_owner`, which is `params.dig('repository', 'owner', 'login')` (fallback `organization.login`): [1](#0-0) [2](#0-1) 
- `Shipit.github(organization:)` looks up per-organization config (`app_id`, `webhook_secret`, etc.) from `secrets.github`, keyed by organization name, and instantiates a `GitHubApp` whose `verify_webhook_signature` only checks the HMAC against that organization's own `webhook_secret`: [3](#0-2) [4](#0-3) 
- Once the signature is accepted, `create` dispatches the *same raw* `params` to the registered handlers: [5](#0-4) 
- Handlers such as `OpenedHandler` (and the shared `ReviewStackAdapter`) resolve the repository to act on using `params.repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

Exploit flow: an attacker who legitimately controls an organization `attacker` that is a configured tenant of the shared Shipit instance (has its own `webhook_secret` entry in `secrets.github`) crafts a raw JSON body where `repository.owner.login = "attacker"` but `repository.full_name = "victim/repo"`. They compute `X-Hub-Signature` over that raw body using their own known `webhook_secret` and POST it to `/webhooks` with `X-Github-Event: pull_request`. `verify_signature` looks up `Shipit.github(organization: "attacker")`, verifies successfully against the attacker's own secret, and the request proceeds. `OpenedHandler`/`ReviewStackAdapter` then operate on `Shipit::Repository.from_github_repo_name("victim/repo")`, creating/archiving/unarchiving review stacks, writing `PullRequest` records, and mutating provisioning state for the victim repository — a repository the attacker never authenticated for.

No existing guard prevents this: `verify_signature` never compares `repository.owner.login` to the owner segment of `repository.full_name`; `drop_unhandled_event` only checks event type; the `ExplicitParameters` schemas (e.g. in `OpenedHandler`) validate field *types/presence*, not cross-field consistency; and `Repository.from_github_repo_name` performs no ownership check against `repository_owner`.

### Impact Explanation
An attacker who controls any one Shipit-configured GitHub organization can forge webhook events that create, archive, unarchive, or mutate `Stack`/`PullRequest`/review-stack records for **any other tracked repository on the same Shipit instance**, regardless of organizational boundary. This is repeatable for every `pull_request`/`push`/`status`/`membership`/`check_suite` handler that resolves its target via `repository.full_name` (or similarly untied fields) rather than the verified `repository_owner`. This breaks tenant isolation on a shared Shipit deployment: one org's payload mutates another org's stack/task/PR state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Requires the attacker to control at least one GitHub organization that the Shipit operator has already configured as a legitimate multi-tenant entry (with its own `app_id`/`webhook_secret` in `secrets.github`) — this is the explicit precondition stated in the question and is a realistic scenario for any shared/multi-org Shipit instance (Shipit natively supports multiple organizations via `github_app_config`). Beyond that, the attack costs a single crafted HTTP POST with a correctly computed HMAC over an attacker-controlled body — no GitHub interaction, no live network access to GitHub, fully reproducible offline. It is trivially repeatable against any victim repository name Shipit tracks.

### Recommendation
After signature verification succeeds, re-derive the "authenticated organization" and require it to match the owner segment of `repository.full_name` (and any other repository identifiers used by the handler) before dispatching to handlers — e.g., reject the request if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`. More robustly, look up the `Shipit::Repository` first from `repository.full_name`, determine its actual owning organization, and verify the signature using that organization's secret rather than trusting `repository.owner.login` supplied in the same untrusted payload.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (no live GitHub required):
1. Configure a dummy multi-org secrets fixture with two orgs, `attacker` and `victim`, each with distinct `webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Create `shipit_repositories(:victim)` = `"victim/repo"` tracked in Shipit, review-stacks enabled with `allow_all`.
3. Build a `pull_request` "opened" JSON payload where `payload['repository']['owner']['login'] = 'attacker'` and `payload['repository']['full_name'] = 'victim/repo'`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', attacker_webhook_secret, raw_body)`.
5. POST to `/webhooks` with headers `X-Github-Event: pull_request` and the computed signature.
6. Assert response is `200 OK` (not `422`), and assert:
   - `assert_equal "attacker", <value passed into Shipit.github(organization:) during verify_signature>` (signature bound to attacker's org)
   - `assert_equal "victim/repo", <Shipit::Repository resolved by OpenedHandler>.full_name` (mutation target is victim's repo)
   - `assert_difference -> { Shipit::Stack.where(repository: shipit_repositories(:victim)).count }` shows a new/updated stack for `victim/repo`, proving the two sides of the equality diverge and victim's records were mutated by attacker-signed traffic.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```

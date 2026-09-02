### Title
Signature verification keyed on `repository.owner.login` while handlers resolve state via `repository.full_name` allows cross-org PullRequest mutation - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the webhook secret) used to validate the incoming request based solely on `repository.owner.login`, while `AssignedHandler` (like all `pull_request` handlers) resolves the `Repository`/`Stack`/`PullRequest` to mutate using the unrelated `repository.full_name` field. Because `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization has no `webhook_secret` configured, an attacker who can name (or find) a no-secret organization in `repository.owner.login` passes verification for free while pointing `repository.full_name` at a victim org's repository, letting `AssignedHandler` write to that victim's `PullRequest` record.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`organization_that_authenticated_the_request == organization_that_owns_the_mutated_repository`, i.e. `repository_owner (params.dig('repository','owner','login')) == Repository.from_github_repo_name(params.repository.full_name).owner`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` purely from `params.dig('repository', 'owner', 'login')` [1](#0-0)  and uses it to select the `GitHubApp` instance: `Shipit.github(organization: repository_owner)` [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` if that particular organization has no `webhook_secret` configured: `return true unless webhook_secret` [3](#0-2) . This means any org present in `secrets.github` without a configured `webhook_secret` (or, in single-app mode, any request at all since only one shared secret exists) authenticates arbitrary payloads under that org's name.
3. Once `verify_signature` passes, `create` dispatches the raw JSON `params` — untouched — to the handler chain: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) . Nothing re-checks that `repository_owner` matches `params.repository.full_name`.
4. `AssignedHandler#process` looks up the repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a field completely independent of the one used to pick the signing secret [5](#0-4) , then finds and updates the persisted `PullRequest` for that repository's stack: `pull_request.update(github_pull_request: params.pull_request) if pull_request.present?` [6](#0-5) .

Attacker request: `POST /webhooks` with header `X-Github-Event: pull_request`, a signature computed against (or matching, since no secret exists for) some org `evil-org` that has no `webhook_secret` entry in `secrets.github`, body:
```json
{
  "action": "assigned",
  "number": <victim PR number>,
  "pull_request": { ... attacker-controlled fields ... },
  "repository": { "owner": {"login": "evil-org"}, "full_name": "victim-org/victim-repo" },
  "sender": {"login": "attacker"}
}
```
`verify_signature` resolves `Shipit.github(organization: 'evil-org')`, finds no `webhook_secret`, and accepts unconditionally. `AssignedHandler` then resolves `victim-org/victim-repo` via `full_name` and updates that stack's `PullRequest` row with attacker-supplied `github_pull_request` JSON — a write for a repository/stack that never authenticated the request.

Why guards fail: `drop_unhandled_event` and `check_if_ping` don't touch payload content; `ExplicitParameters` schema on `AssignedHandler` only validates types/presence of `repository.full_name`, not consistency with `repository.owner.login`; there is no `GithubOrganizationUnknown` raised because `evil-org` is a *known*, just secret-less, org. Multi-org GitHub App configuration (`github_app_config`/`TOP_LEVEL_GH_KEYS`, confirmed in `lib/shipit.rb`) is exactly the feature that lets different orgs have different (or absent) secrets, which is what makes the split exploitable.

### Impact Explanation
An attacker who controls (or can name) any organization configured in Shipit without a `webhook_secret` can forge `pull_request` webhooks that mutate `PullRequest` records belonging to a completely different organization's stack, including production-environment stacks — a cross-tenant write ("a payload for one repository mutating another's stack, commit, task or team"), matching the Critical impact category. The blast radius spans every stack/repository configured in the multi-org Shipit instance, since the attacker only needs one weakly-configured org to forge events against any other org.

### Likelihood Explanation
Preconditions: Shipit must be configured with per-organization GitHub App settings (`secrets.github` keyed by org) where at least one configured organization lacks a `webhook_secret`, and the target victim repository/stack must be registered under a different organization. This is plausible in real deployments (e.g., an org added for testing/onboarding without a secret yet configured, or intentionally left blank). No authentication, session, or GitHub credentials are required by the attacker — only the ability to send an HTTP POST to `/webhooks`, which is explicitly unauthenticated. The attack is fully repeatable and requires no special timing.

### Recommendation
Do not select the verification secret based on a field independent from the field the handlers use to identify the target repository. Verify the webhook signature using the organization/repository derived from `repository.full_name` (or cross-check `repository.owner.login` against the owner segment of `repository.full_name` before proceeding), and treat a missing `webhook_secret` as a configuration error to reject (or fail closed) rather than an automatic pass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, illustrative — actual file changes out of scope per rules but included for validation):
1. Configure `secrets.github` with two orgs: `evil-org` (no `webhook_secret` key) and `victim-org` (with a `webhook_secret`).
2. Create a `victim-org/victim-repo` `Repository`, a production `Stack`, and a `PullRequest` fixture with `number: 42`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, no valid signature for `victim-org`, and body: `{"action":"assigned","number":42,"pull_request":{...attacker-controlled...},"repository":{"owner":{"login":"evil-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`.
4. Assert response is `200 OK` (verification passed via `evil-org`'s absent secret) and assert the `PullRequest` record for `victim-org/victim-repo` was updated with the attacker's `github_pull_request` payload — proving `binding: repository_owner ('evil-org') != repository.full_name owner ('victim-org')` yet the write still succeeded.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

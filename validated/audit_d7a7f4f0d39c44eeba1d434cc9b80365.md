## Analysis

Confirmed vulnerability, but the mechanism differs slightly from the question's framing. The key facts:

- `Shipit::WebhooksController#verify_signature` picks the GitHub app config via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from `params.dig('repository', 'owner', 'login')` [1](#0-0) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization — the malformed/nil-signature split path (`signature.split("=", 2)` yielding `algorithm`/`nil`) never even executes because of this early return: `return true unless webhook_secret` [2](#0-1) .
- Separately, `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler` resolves the target `Repository`/stack using `params.repository.full_name` via `Repository.from_github_repo_name` [3](#0-2) , then persists `params.pull_request.labels.map(&:name)` onto `stack.pull_request` [4](#0-3) .
- Critically, `repository.owner.login` (used for signature-org lookup) and `repository.full_name` (used for stack lookup) are two **independently attacker-controlled fields in the same raw JSON body** — nothing in `WebhooksController`, `ExplicitParameters` schemas, or the handler enforces that they refer to the same tenant/org. `Repository.from_github_repo_name` just splits `full_name` on `/` and looks it up in Shipit's own DB `find_by(owner:, name:)` [5](#0-4) .

So the invariant "the organization whose webhook_secret verified the request equals the organization that owns the repository/stack the handler writes" **is broken**: an attacker can set `repository.owner.login = "org-with-no-secret"` (any configured-but-secretless org, or any org name at all in single-app mode since `Shipit.github(organization:)` falls back to the single global app config whenever `github_default_organization` is `nil`, ignoring the passed org entirely [6](#0-5) ) while setting `repository.full_name = "victim-org/victim-repo"` to point at a completely different, real, secured stack. `verify_signature` passes (trivially, since no secret configured / single-app mode), and `LabelCapturingHandler` then mutates the victim repo's `PullRequest` record based on `full_name`, independent of the org used for signature verification.

This means the described exploit is real, but the root cause is a **field-confusion between `repository.owner.login` (used for auth) and `repository.full_name` (used for the write)** within a single payload, not specifically the malformed-signature-split detail from the question (that detail is actually moot — the no-secret short-circuit bypasses signature checking entirely before the split ever matters).

### Title
Webhook signature verification is scoped to `repository.owner.login` while the mutating handler trusts `repository.full_name`, allowing cross-repository writes when the referenced owner has no `webhook_secret` — (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` gates the request using `params.repository.owner.login`, but `verify_webhook_signature` returns `true` unconditionally when that org has no secret configured (or when Shipit runs in single-app mode, where the org argument is ignored entirely). The actual mutation performed by `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler` looks up the target `Repository`/stack via the independently-controlled `repository.full_name` field in the same JSON body, so an attacker can make these two fields diverge and write to a repository/org that never authenticated the request.

### Finding Description
The broken binding is: *the org identified by `repository.owner.login` (used to select the `webhook_secret` for verification) equals the org that owns `repository.full_name` (used by the handler to locate the `Repository`/`Stack`/`PullRequest` to mutate)*. Nothing enforces this equality.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [7](#0-6) .
2. `GitHubApp#verify_webhook_signature` short-circuits `return true unless webhook_secret` — if that org has no secret configured, verification always succeeds regardless of the `X-Hub-Signature` header content, including a malformed one with no `=` [2](#0-1) . In single-app deployments, `Shipit.github(organization:)` ignores the passed `organization` altogether and always returns the single configured app [6](#0-5) .
3. `WebhooksController#create` then dispatches the raw JSON `params` to all registered handlers for the event [8](#0-7) .
4. `LabelCapturingHandler#repository` resolves the target repo from `params.repository.full_name`, completely independent of the `repository.owner.login` value used in step 1 [9](#0-8) , and `capture_labels` writes attacker-supplied label names into `stack.pull_request` [4](#0-3) .

Exploit request: attacker POSTs a `pull_request`/`reopened` JSON body with `repository.owner.login` set to any org that has no `webhook_secret` configured (or any string, if Shipit is deployed in single-app mode), but `repository.full_name` set to `"victim-org/victim-repo"` — an existing, unrelated stack. `X-Hub-Signature` can be omitted, malformed, or anything, since it is never actually checked in this branch.

Existing guards fail because: `verify_signature` never validates that `repository.owner.login` and `repository.full_name`'s owner segment agree; the `ExplicitParameters` schema on the handler only requires `repository.full_name` to be present as a `String` with no cross-field consistency check against the org used upstream for auth [10](#0-9) ; and `Repository.from_github_repo_name` performs a raw DB lookup with no tenant/ownership check tied to the authenticated org [5](#0-4) .

### Impact Explanation
An unauthenticated attacker can mutate `PullRequest#labels` for any tracked review stack in the Shipit instance without ever knowing that repository's `webhook_secret`, as long as some org configured in Shipit lacks a secret (or Shipit runs single-app). Since labels become uppercased environment variable keys injected via `ReviewStack#env` (per the question's stated downstream effect), this is a cross-repository/cross-tenant state manipulation that could influence CI/CD provisioning behavior or environment for a target stack the attacker does not own — matching "Critical: payload for one repository mutating another's stack/commit/task."

### Likelihood Explanation
Requires a Shipit deployment where at least one configured org has no `webhook_secret` (explicitly shown as the default/example configuration with `webhook_secret: # nil`), or a single-app (non-multi-org) deployment, both of which are documented, common configurations. No secrets, tokens, or privileged access are required — only knowledge of a target stack's `owner/repo` full name, which is often public. This is trivially repeatable against any tracked repository.

### Recommendation
Enforce that the org used for signature verification matches the org embedded in `repository.full_name` (reject if they diverge), and/or require `verify_webhook_signature` to fail closed (not bypass) whenever a webhook is attributed to a different repo/org than the one being mutated. Additionally, consider requiring a `webhook_secret` to be mandatory for all configured orgs, and validate `repository.owner.login` downcase matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
Minitest plan (functional/integration test on `Shipit::WebhooksController`):
1. Configure `Shipit.stubs(:github)` such that `Shipit.github(organization: 'no-secret-org')` returns a `GitHubApp` with `webhook_secret` nil (asserting `verify_webhook_signature` returns `true` for any signature, including `"garbagewithoutequals"`).
2. Create a real `Repository`/`Stack`/`ReviewStack` fixture owned by `"victim-org/victim-repo"` with an existing `PullRequest`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, `X-Hub-Signature: "garbagewithoutequals"`, and JSON body where `repository.owner.login == "no-secret-org"` but `repository.full_name == "victim-org/victim-repo"`, `action == "reopened"`, and `pull_request.labels == [{name: "PWNED"}]`.
4. Assert response is `200 OK` (not `422`).
5. Assert `victim_repo.pull_request.reload.labels == ["PWNED"]` — proving the value written was attributed to `"no-secret-org"` for auth purposes but mutated `"victim-org"`'s record, i.e., assert `payload_repository_owner != victim_repository.owner` while the write still succeeded.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

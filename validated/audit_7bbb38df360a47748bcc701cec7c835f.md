### Title
Forged `pull_request`/`unlabeled` webhook bypasses signature scoping via `repository.owner.login`/`organization.login` divergence from `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's GitHub App/secret validates a webhook using `repository_owner`, computed from `params.dig('repository','owner','login')` with a fallback to `params.dig('organization','login')` [1](#0-0) . The `pull_request` handlers (e.g. `UnlabeledHandler`) instead resolve the repository to mutate from a completely independent field, `params.repository.full_name` [2](#0-1) . Nothing enforces that `repository.owner.login`/`organization.login` is consistent with the owner segment of `repository.full_name`, so a forged payload can be verified under one organization's (weak or secret-less) configuration while mutating another organization's review-stack state.

### Finding Description
The broken invariant, stated as an equality that the code assumes but never enforces:
`repository_owner (params.dig('repository','owner','login') || params.dig('organization','login'))` == `owner_of(params.repository.full_name)` (the value used by `Repository.from_github_repo_name`).

Trace:
1. `WebhooksController#create` parses `params = JSON.parse(request.raw_post)` and dispatches `Shipit::Webhooks.for_event(event)` to every registered handler for that event, unconditionally passing the raw hash [3](#0-2) . For `pull_request`, this fans out to `OpenedHandler, ClosedHandler, ReopenedHandler, EditedHandler, AssignedHandler, LabeledHandler, UnlabeledHandler, LabelCapturingHandler` [4](#0-3) .
2. Before `create` runs, `verify_signature` picks the verifying `GitHubApp` via `Shipit.github(organization: repository_owner)`, where `repository_owner` reads `repository.owner.login`, falling back to `organization.login` if `repository` (or that nested key) is absent [5](#0-4) .
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected organization's config has no `webhook_secret` set: `return true unless webhook_secret` [6](#0-5) . `webhook_secret` is optional per-org config (`@webhook_secret = @config[:webhook_secret].presence`) [7](#0-6) .
4. `UnlabeledHandler` (and its sibling PR handlers) never looks at `repository.owner.login` or `organization.login`. It resolves the target `Repository` purely from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [2](#0-1) , then archives/unarchives that repository's review stack based on label state [8](#0-7) .

Exploit flow: an attacker crafts a `pull_request`/`unlabeled` payload where `repository.full_name = "victim-org/victim-repo"` (the tenant/repo they want to mutate) but sets `repository.owner.login` (or omits `repository.owner` and instead sets top-level `organization.login`) to any GitHub org that is configured in the host's Shipit `github.apps` config **without** a `webhook_secret`. `verify_signature` resolves the app for that secret-less org, and `verify_webhook_signature` returns `true` for any signature/body since `webhook_secret` is blank — the request passes verification with no valid signature at all. The handler set for `pull_request` then executes against `victim-org/victim-repo`'s actual `Repository` record and its review stack, archiving/unarchiving/deprovisioning it despite the request never being authenticated by `victim-org`'s secret.

Existing guards do not prevent this: `verify_signature` only checks the signature against the org it derives from `repository.owner.login`/`organization.login`, never cross-checks it against `repository.full_name`; `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` in `UnlabeledHandler` requires `repository.full_name` to be a `String` but does not require or check `repository.owner` at all [9](#0-8) ; there is no model-level validation tying a webhook's authenticating organization to the repository record being mutated.

### Impact Explanation
An attacker with no Shipit credentials can flip `archive!`/`unarchive!` and provisioning state (`deprovisioning`) on another organization's review-stack-backed `Stack`, entirely bypassing that organization's webhook secret — this is exactly the "payload for one repository mutating another's stack" Critical category. The same divergence also affects `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, and `LabelCapturingHandler`, all of which key off `params.repository.full_name` for `Repository.from_github_repo_name` lookups while `repository_owner` drives the signature check independently, so the blast radius spans stack creation/archival/label-capture across any repository registered in the Shipit instance [10](#0-9) . This is repeatable per request and is not limited to a single victim repo — any repository with `review_stacks_enabled` and a known `full_name` can be targeted, as long as one configured org in the deployment lacks a `webhook_secret`.

### Likelihood Explanation
Exploitation requires a precondition external to the attacker: at least one GitHub organization configured in the host's Shipit `github.apps`/secrets config with no `webhook_secret` set (or, out of scope per the rules, one whose secret the attacker already knows). This is a plausible operational state — `webhook_secret` is optional in `GitHubApp#initialize` and a multi-tenant Shipit install onboarding a new org, or a test/staging org, could easily have it unset before rotation [7](#0-6) . Given that precondition, the attacker cost is a single crafted HTTP POST with attacker-chosen JSON, no valid signature required, and no session/token — fully repeatable and automatable.

### Recommendation
Cross-validate `repository.full_name`'s owner segment against the same field used to select the verifying `GitHubApp` (`repository_owner`) before dispatching to handlers, and reject the payload (422) on mismatch. Additionally, require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and consider validating in each handler that the resolved `Repository#owner` matches the organization that authenticated the request.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/pull_request/unlabeled_handler_test.rb` style):
1. Configure two orgs in test secrets: `victim-org` with a `webhook_secret`, and `attacker-org` with no `webhook_secret` (mirroring `lib/shipit/github_app.rb` optional config).
2. Create `shipit_repositories(:victim)` with `owner: "victim-org"`, `name: "victim-repo"`, `review_stacks_enabled: true`, `provisioning_behavior: allow_with_label`, with an existing non-archived `Stack`/review stack for a PR.
3. Build payload: `action: "unlabeled"`, `pull_request.state: "open"`, `pull_request.labels: []` (label absent triggers `archive?`), `repository.full_name: "victim-org/victim-repo"`, `repository.owner.login: "attacker-org"` (no `organization` key needed once `repository.owner.login` is set).
4. Assert: `Shipit.github(organization: "attacker-org").verify_webhook_signature(anything, anything)` returns `true` (no secret configured) — i.e., the equality `repository_owner == owner_of(repository.full_name)` is `"attacker-org" != "victim-org"` yet verification still passes.
5. POST to `/webhooks` with header `X-Github-Event: pull_request` and any/garbage `X-Hub-Signature`.
6. Assert `response.status == 200` and `victim_stack.reload.archived? == true` (or `provision_status == "deprovisioning"`), proving the victim's stack was mutated by a request that never used `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** lib/shipit/github_app.rb (L44-50)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

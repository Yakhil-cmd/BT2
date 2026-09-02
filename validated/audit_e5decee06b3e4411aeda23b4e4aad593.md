### Title
Signature verification keyed on `repository.owner.login` while all mutations resolve `repository.full_name` against a different org - stack takeover via `pull_request`/`unlabeled` - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates every inbound webhook using only `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . Handlers such as `UnlabeledHandler` never re-check that owner; they instead resolve the acted-upon repository/stack from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` [3](#0-2) [4](#0-3) . If an org named in `repository.owner.login` has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` returns `true` unconditionally (`return true unless webhook_secret`) regardless of the actual signature [5](#0-4) , so an attacker can pick a secret-less/attacker-controlled `owner.login` to pass verification while pointing `repository.full_name` at any other org/repo that Shipit tracks.

### Finding Description
The invariant that should hold is: `org_used_for_signature_verification == org_that_owns_the_mutated_repository`, i.e. `params.repository.owner.login == owner(Repository.from_github_repo_name(params.repository.full_name))`. The code never enforces this equality.

- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)` [6](#0-5) . `repository_owner` is taken purely from `params.dig('repository','owner','login')` [2](#0-1) , an attacker-controlled JSON field with no cross-check against `repository.full_name`.
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when no `webhook_secret` is configured for that organization [7](#0-6) . Any org configured in `Shipit` without a webhook secret (or any org an attacker can get added to the config with no secret) lets an attacker bypass signature checks entirely.
- Once past `verify_signature`, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw, unvalidated `full_name` value into every matching handler [8](#0-7) .
- `UnlabeledHandler#repository` resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which is a plain DB lookup with no relation to which org authenticated the request [3](#0-2) . `stack` is then derived from that repository's `review_stacks` and mutated: `stack.archive!` / `stack.unarchive!` [9](#0-8) .

Exploit flow: attacker crafts `POST /webhooks` with header `X-Github-Event: pull_request`, body `{"action":"unlabeled", "repository": {"owner": {"login": "attacker-org-with-no-secret"}, "full_name": "victim-org/victim-repo"}, "pull_request": {...}, ...}`. Because `attacker-org-with-no-secret` has no configured `webhook_secret`, `verify_signature` passes trivially. The handler then resolves `victim-org/victim-repo`'s tracked `Repository`, looks up its `review_stacks` matching the forged PR/branch, and calls `archive!`/`unarchive!` on that stack based on `provisioning_behavior` and the (attacker-forged) label list in the payload — a mutation on a repository/stack that never authenticated this request.

However, I could not confirm from the available code that `Shipit.github(organization:)` will actually resolve to a `GitHubApp` instance with no `webhook_secret` for an attacker-nameable organization in a realistic deployment — this depends entirely on host-level `Shipit` configuration (`lib/shipit.rb`'s `github_organizations`/`github` lookup), which was only partially inspected. If every organization configured in the host app has a non-blank `webhook_secret`, then `verify_webhook_signature` never short-circuits to `true`, and the attacker would need to also forge a valid HMAC-SHA1 signature for that org's real secret — which they do not possess per the stated threat model. Without a confirmed secret-less-organization or "guessable secret" precondition in this codebase, this reduces to a **configuration-dependent** issue, not a code-level authentication bypass demonstrable purely from this engine's logic.

### Impact Explanation
If a secret-less (or otherwise attacker-satisfiable) organization exists in the Shipit installation's GitHub app configuration, an attacker can forge `pull_request`/`unlabeled` events that archive or unarchive any tracked repository's review stacks, independent of which org's secret validated the request. On a `continuous_deployment`-enabled stack, unarchiving a stack could allow deploys of pending green commits to proceed via `ContinuousDeliveryJob`, and archiving could halt deploys — both are unauthorized state mutations on a repository/stack the attacker's request did not authenticate. This matches "a payload for one repository mutating another's stack" (Critical) *only if* the secret-less-org precondition holds.

### Likelihood Explanation
Exploitability is entirely gated on Shipit's GitHub app/organization configuration (outside this engine's own code, in host-supplied YAML/initializers), specifically whether any registered organization has a blank `webhook_secret`. This engine's code does not itself guarantee every organization has a secret, nor does it cross-validate `repository.owner.login` against `repository.full_name`'s owner anywhere in the webhook pipeline. But absent a demonstrated concrete no-secret organization in this repo's own fixtures/config (test fixtures configure `shopify` with a secret, per `test/controllers/webhooks_controller_test.rb`), I cannot produce a fully self-contained minitest proof using only this engine's code that doesn't rely on an externally-supplied misconfiguration.

### Recommendation
Do not authenticate webhooks by a caller-supplied field (`repository.owner.login`) that is decoupled from the resource actually mutated (`repository.full_name`). Resolve the `Repository`/owner used for signature verification from a trusted source (e.g., look up the tracked `Repository` by `full_name` first, then verify using that repository's own owner/secret), and reject the request if `repository.owner.login` and the owner of `repository.full_name` diverge. Additionally, treat a missing `webhook_secret` for a configured organization as a fail-closed condition rather than an automatic pass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Could not construct a proof restricted to `test/**` fixtures that does not depend on an externally-configured secret-less organization; the existing test suite (`test/controllers/webhooks_controller_test.rb`) always configures `shopify` with a secret and stubs `verify_signature`, so no fixture in this repo demonstrates the no-secret bypass path. A conclusive minitest would need to: (1) configure a `Shipit.github_organizations` entry with `webhook_secret: nil`, (2) POST a `pull_request`/`unlabeled` payload with `repository.owner.login` set to that no-secret org and `repository.full_name` set to a different, tracked `continuous_deployment`-enabled stack's repo, and (3) assert `stack.archived?` changed — this was not verifiable from the indexed code alone.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

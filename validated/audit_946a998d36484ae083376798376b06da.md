### Title
Signature verification org (`repository.owner.login`) is never checked against the mutated resource's org (`repository.full_name`), letting a no-secret org's webhook archive another org's `ReviewStack` - ([File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate an incoming webhook solely from `params.dig('repository','owner','login')`, while every `pull_request` handler (including `ClosedHandler`) resolves the *target* repository/stack solely from `params.repository.full_name`. These two payload fields are never checked for equality, so in a multi-org Shipit deployment an attacker who can trigger delivery of a webhook that is "authenticated" against a no-secret org can point `full_name` at a completely different org's tracked repository and have `ClosedHandler` archive that repository's `ReviewStack`.

### Finding Description
The broken binding, stated explicitly, is:
`repository_owner (used to pick the verifying GitHubApp/secret) == owner(Repository.from_github_repo_name(params.repository.full_name)) (the repo actually mutated)`
This equality is never asserted anywhere in the request path.

Code path:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and calls `Shipit.github(organization: repository_owner)` to pick a `GitHubApp` instance, then calls `verify_webhook_signature` on it. [1](#0-0) [2](#0-1) 
2. `Shipit.github` in multi-org mode looks up `secrets.github[organization]`; if that org isn't configured it raises `GithubOrganizationUnknown` (caught → 422), but if the org **is** configured with no `webhook_secret`, `GitHubApp#verify_webhook_signature` returns `true` unconditionally: `return true unless webhook_secret`. [3](#0-2) [4](#0-3) 
3. Once the request passes `verify_signature`, `WebhooksController#create` dispatches the *entire raw JSON payload* to all handlers for the event, with no re-derivation or re-check of which org/repo actually "owns" the signature that was verified. [5](#0-4) 
4. `ClosedHandler#process` never inspects `repository.owner.login` at all. It resolves the target `Repository` purely from `params.repository.full_name` via `Repository.from_github_repo_name`, builds a `ReviewStackAdapter` scoped to `repository.review_stacks`, and calls `archive!` if `params.action == "closed"`. [6](#0-5) 
5. `ReviewStackAdapter#archive!` finds the stack by `environment: "pr#{params.number}"` within that scope and, if present and not already archived, calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!(user)`. [7](#0-6) 

Exploit flow: an unprivileged actor who can cause delivery of an arbitrary `pull_request` webhook body to `POST /webhooks` (e.g., by triggering a webhook from a repository under an org that is registered in Shipit's multi-org GitHub config but has no `webhook_secret` set) crafts a payload with:
- `repository.owner.login = "no-secret-org"` (selects the org whose `webhook_secret` is blank, so signature check is vacuously satisfied)
- `repository.full_name = "victim-org/victim-repo"` (a different, tracked repository with `review_stacks_enabled = true`, `provisioning_behavior = allow_all`)
- `action = "closed"`, `number = <victim PR number>`

Because `review_stacks_enabled`/`allow_all` on the victim repo means legitimate PR activity already auto-provisions `ReviewStack`s that execute `shipit.yml` on open, a matching stack for that PR number already exists under `victim-repo.review_stacks`. The forged `closed` webhook is accepted (signature check trivially true for the no-secret org) and dispatched unmodified to `ClosedHandler`, which archives/deprovisions the victim's `ReviewStack` — a write on a repository/stack that never authenticated the request.

Existing guards that fail to close this gap:
- `verify_signature` only validates that *some* configured org's secret matches (or is absent) — it never compares that org to `repository.full_name`'s owner.
- `drop_unhandled_event` and the `ExplicitParameters` schema in `ClosedHandler` only validate payload shape (`requires :repository { requires :full_name }`), not cross-consistency with `repository.owner.login`. [8](#0-7) 
- No model validation (`Repository`, `Stack`) or controller code re-derives the owner from `full_name` and compares it to the org used for signature verification.

### Impact Explanation
`ClosedHandler` archives and deprovisions a `ReviewStack` belonging to a repository that never authenticated the request — this is exactly the "payload for one repository mutating another's stack" category called out as Critical. The attack is repeatable against any repository/PR number pair as long as the attacker can select an org in the multi-org config whose `webhook_secret` is blank; each request can archive one target `ReviewStack` by PR number, and can be repeated across arbitrary tracked repositories/orgs sharing the same Shipit instance. Blast radius is bounded to deployments using Shipit's multi-org GitHub App configuration (`github_default_organization` present) with at least one org lacking a `webhook_secret`; single-org deployments are not affected because `Shipit.github` ignores the `organization` argument entirely when `github_default_organization` is `nil` and always uses the single global secret.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (`secrets.github` keyed by organization), (2) at least one configured org with no `webhook_secret` set, (3) the attacker being able to trigger a `POST /webhooks` delivery labeled with that no-secret org's login while pointing `full_name` at a victim repository, and (4) that victim repository having `review_stacks_enabled: true` / `allow_all` so a `ReviewStack` for the targeted PR already exists. Given these preconditions, the attacker needs no secrets, no session, and no repository access to the victim — the request can be sent directly with `curl`/HTTP to `/webhooks`, making it trivially repeatable. The precondition of a "no-secret org" existing in a multi-org config is an operator misconfiguration, so likelihood scales with how many Shipit deployments run multi-tenant with incomplete secret provisioning.

### Recommendation
After signature verification succeeds, re-derive the organization from `params.repository.full_name` (the field actually used by the handlers) and require it to equal the `repository_owner` used to select the verifying `GitHubApp`/secret; reject the request (422) on mismatch. Alternatively, disallow registering an org in the multi-org config with a blank `webhook_secret`, and/or make `GitHubApp#verify_webhook_signature` fail closed (return `false`) rather than `true` when `webhook_secret` is blank.

### Proof of Concept
Minitest plan (no live GitHub, under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/pull_request/closed_handler_test.rb`):
1. Configure `secrets.github` with two orgs: `no_secret_org` (no `webhook_secret` key) and the victim org used by fixture repository `shipit_repositories(:shipit)`.
2. Set the victim repository/stack: `review_stacks_enabled = true`, `provisioning_behavior = :allow_all`; create an active `ReviewStack` fixture with `environment: "pr#{n}"` for PR number `n`, not archived.
3. Build a `pull_request` `closed` payload where `repository.owner.login = "no_secret_org"` and `repository.full_name = "<victim-org>/<victim-repo>"`, `number = n`.
4. `POST /webhooks` with header `X-Github-Event: pull_request` and a bogus/absent `X-Hub-Signature` (since `no_secret_org` has no secret, `verify_webhook_signature` returns `true` unconditionally).
5. Assert:
   - Binding before: `repository_owner == "no_secret_org"`, actual mutated repo owner `== "<victim-org>"` — unequal.
   - Response status is `200`/`:ok` (not `422`), proving signature check passed despite the mismatch.
   - `ReviewStack` fixture `.reload.archived?` is now `true` (or `awaiting_provision`/`deprovisioned` state changed), proving the victim's stack was mutated by a request authenticated under a different org's (non-)secret.
   - Binding after: still unequal, yet the write occurred — demonstrating the invariant "a `pull_request` event only affects the repository/stack whose secret authenticated it" is violated.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
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

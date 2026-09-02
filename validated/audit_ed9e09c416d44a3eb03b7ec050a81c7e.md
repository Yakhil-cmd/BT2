### Title
Cross-tenant ReviewStack unarchival via mismatched HMAC-verified `repository.owner.login` vs. handler-resolved `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook payload using `Shipit.github(organization: repository_owner)`, where `repository_owner` is derived from `params.dig('repository', 'owner', 'login')`. `ReopenedHandler#repository` (and every other `pull_request` handler) instead resolves the target `Shipit::Repository` from a completely independent field, `params.repository.full_name`. Because these two fields are never cross-validated, an attacker who controls a repository (`attacker-org/whatever`) with a valid, correctly configured webhook secret can craft a raw JSON body where `repository.owner.login` is `attacker-org` (so HMAC verification succeeds against `attacker-org`'s secret) while `repository.full_name` is `victim-org/victim-repo`, causing the handler to write to `victim-org`'s `ReviewStack`.

### Finding Description
The binding the security model relies on is: **the organization whose secret verified the request bytes == the organization owning the repository record the handler mutates**, i.e. `repository_owner (used for HMAC) == owner(Repository.from_github_repo_name(repository.full_name))`.

Tracing the code:
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` computes `repository_owner` via `repository_owner` (line 59-62: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`), fetches `Shipit.github(organization: repository_owner)`, and verifies `X-Hub-Signature` against `request.raw_post` using that org's `webhook_secret`.
- `create` (lines 10-15) re-parses `request.raw_post` and dispatches to `Shipit::Webhooks.for_event(event)` handlers, passing the full parsed hash as `payload`.
- `ReopenedHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:49-53`) resolves the target repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a schema field entirely distinct from `repository.owner.login`.
- `ReopenedHandler#process` (lines 41-45) calls `stack.unarchive!` when `respond_to_pull_request_reopened?` is true, gated only by `repository.review_stacks_enabled` and `repository.provisioning_behavior_allow_all?` (etc.) on the *resolved* (victim) repository — not on any property of the authenticating organization.
- `stack` (lines 55-59) builds a `ReviewStackAdapter` scoped to `repository.review_stacks`, i.e., the victim repository's own `review_stacks` association, and `ReviewStackAdapter#unarchive!`/`create!` (`review_stack_adapter.rb:37-50`, `72-85`) creates/unarchives a `Shipit::ReviewStack` row under that scope.

Exploit flow: attacker owns `attacker-org/whatever`, which has a legitimately configured `Shipit::GitHubApp` with a known `webhook_secret` (attacker configured their own GitHub App/webhook against their own repo, which is a normal, unprivileged setup step — no Shipit or victim secret needed). Attacker computes HMAC-SHA1/256 of a crafted raw body using their own secret and POSTs to `/webhooks` with `X-Github-Event: pull_request` and body:
```json
{"action":"reopened","repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"},"pull_request":{...,"head":{"ref":"x","sha":"x"},"labels":[],"assignees":[],"user":{"login":"attacker"}},"number":1,"sender":{"login":"attacker"}}
```
`verify_signature` looks up `Shipit.github(organization: 'attacker-org')`, verifies successfully (attacker's own secret matches attacker's own signature), and `head(422)` is never called. Every `params.dig` used to pull the field for auth is disjoint from every `params.*` field used by the handler to select the write target.

Existing guards do not catch this: `verify_signature` never checks that `repository_owner == Repository.from_github_repo_name(repository.full_name)&.owner`; `ExplicitParameters` schema in the handler (lines 8-39) only validates types/presence, not cross-consistency with the authenticated org; `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) performs a plain `find_by(owner:, name:)` lookup with no ownership check against the request's signing org; there is no `force_github_authentication`, session, or `current_user` check in this flow at all since webhooks are inherently unauthenticated except via HMAC.

### Impact Explanation
A single crafted, self-signed HTTP POST from an attacker who owns any repository with its own configured GitHub App/webhook secret can create or unarchive a `Shipit::ReviewStack` for an arbitrary victim repository that has `review_stacks_enabled` and a permissive `provisioning_behavior`. This can trigger deployment/provisioning workflows (`Shipit::ReviewStackProvisioningQueue.add`, `stack.unarchive!`) for a repository the attacker never authenticated against and does not control. This is repeatable against any repository configured this way, and — depending on what `unarchive!`/provisioning entails downstream (build/deploy triggers) — can result in unauthorized deploys/provisioning actions on victim infrastructure. This matches "Critical - a payload for one repository mutating another's stack" in the impact taxonomy.

### Likelihood Explanation
Preconditions: victim repository must have `review_stacks_enabled` and `provisioning_behavior_allow_all?` (or attacker knows/guesses the provisioning label). Attacker needs only their own Shipit-registered GitHub App/organization with a webhook secret they know (since they configured it) — a fully unprivileged, self-service setup requiring no victim or Shipit operator secret. Cost is a single crafted HTTP request with a valid HMAC computed from the attacker's own known secret. This is trivially repeatable against any number of victim repos matching the precondition.

### Recommendation
In `WebhooksController#verify_signature` (or in each handler's `repository` resolution), enforce that the organization used to verify the HMAC matches the owner of the repository resolved from `repository.full_name` — e.g., after resolving `Shipit::Repository.from_github_repo_name(params.dig('repository','full_name'))`, assert `repository.owner == repository_owner` (case-insensitively) before dispatching to handlers, and reject (422) on mismatch.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, no live GitHub, stub `Shipit.github`):
1. Configure two `GitHubApp` stubs: `Shipit.github(organization: 'attacker-org')` returning a fake app with secret `"attacker-secret"`, and `Shipit.github(organization: 'victim-org')` with a different secret `"victim-secret"`.
2. Create `victim_repo = shipit_repositories(:victim_org_repo)` (owner `victim-org`, name `victim-repo`) with `review_stacks_enabled: true`, `provisioning_behavior: 'allow_all'`.
3. Build raw JSON body with `repository.owner.login = 'attacker-org'`, `repository.full_name = 'victim-org/victim-repo'`, `action: 'reopened'`, valid `pull_request` payload.
4. Compute `X-Hub-Signature` using `"attacker-secret"` over the raw body.
5. POST to `/webhooks` with header `X-Github-Event: pull_request` and the signed body.
6. Assert response is `200`/`:ok` (not `422`), i.e., **left side** `repository_owner == 'attacker-org'` (verified via attacker's secret) succeeded.
7. Assert a `Shipit::ReviewStack` row now exists scoped to `victim_repo.review_stacks` for `environment: "pr1"` (or existing archived stack is unarchived) — i.e., **right side** `owner(resolved repository) == 'victim-org'`.
8. Assert `'attacker-org' == 'victim-org'` is false, proving the binding is broken and the write occurred cross-tenant despite mismatched authentication. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-85)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

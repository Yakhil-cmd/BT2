### Title
Webhook signature verifier selects org by `organization.login` fallback while `AssignedHandler` mutates a stack chosen by an independent `repository.full_name` field, letting forged `pull_request` `unassigned` events overwrite another repository's `PullRequest` record - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb`)

### Summary
`WebhooksController#repository_owner` selects the org used for signature verification from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `AssignedHandler#repository` resolves the target repository from the independent `params.repository.full_name` field. If the attacker supplies `repository.full_name` (required by the handler's `ExplicitParameters` schema) but omits `repository.owner.login`, the verifier falls back to `organization.login`, an attacker-chosen value. If that org happens to be configured in `Shipit.github_apps` without a `webhook_secret`, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, and the forged event is accepted with no valid signature at all, while `AssignedHandler` still writes to the `PullRequest` belonging to the completely different repository named in `repository.full_name`.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`repository_owner` (used to select the `GitHubApp` config for signature verification in `app/controllers/shipit/webhooks_controller.rb:59-62`) should equal the owner/org of `params.repository.full_name` (used by `AssignedHandler#repository` in `app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb:67-69` to locate the `Repository`/`Stack`/`PullRequest`). These two values are read from independent JSON fields (`organization.login` vs `repository.full_name`) and nothing enforces their consistency.

Path:
1. `Shipit::WebhooksController#create` runs `before_action :verify_signature`, which computes `github_app = Shipit.github(organization: repository_owner)` [1](#0-0) .
2. `repository_owner` falls back to `params.dig('organization', 'login')` when `repository.owner.login` is absent [2](#0-1) .
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved org's config has no `webhook_secret` — `return true unless webhook_secret` [3](#0-2) . So any forged/unsigned payload for an org configured without a secret passes verification.
4. After verification, `create` parses `params` fresh from the raw body and dispatches to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
5. `AssignedHandler` requires `repository.full_name` (but not `repository.owner`) in its `ExplicitParameters` schema, so the attacker can supply `repository.full_name` pointing at an entirely different, real repository/stack while leaving `repository.owner` absent to control step 2's fallback [5](#0-4) .
6. `AssignedHandler#process` looks up the `PullRequest` solely via `params.repository.full_name` and, for `action` in `assigned`/`unassigned`, calls `pull_request.update(github_pull_request: params.pull_request)` — mutating the persisted PR record for that repository's stack [6](#0-5) .

Exploit request: attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request`, a signature header of arbitrary/garbage value, and a JSON body containing `organization.login = "org-without-secret"` (any org configured in the host's `Shipit.github_apps` list but lacking `webhook_secret`), no `repository.owner`, and `repository.full_name = "victim-org/victim-repo"` (a real stack's repository), plus a well-formed `pull_request` object and `action: "unassigned"`. Verification passes unconditionally (step 3), and the handler overwrites `victim-org/victim-repo`'s tracked `PullRequest.github_pull_request` cache with attacker-chosen title/state/assignees/labels/head sha/ref — a cross-repository/cross-tenant unauthenticated write.

Existing guards do not stop this: `drop_unhandled_event` only filters unregistered event types, not payload consistency; the `ExplicitParameters` schema for `AssignedHandler` never requires `repository.owner`, so it cannot enforce owner/full_name consistency; `verify_signature` never cross-checks `repository_owner` against `repository.full_name`'s owner; and `GithubOrganizationUnknown` only protects against orgs that are entirely absent from config, not against configured-but-secretless orgs.

### Impact Explanation
An unauthenticated internet attacker can overwrite the `github_pull_request` payload cached on any `Shipit::PullRequest` record for any repository/stack hosted on the instance, provided the instance has at least one GitHub org/app configured without a `webhook_secret` (regardless of which org actually owns the target repository). This is a payload-for-one-repository-mutating-another's-stack scenario, matching the Critical impact category. It is fully repeatable against arbitrary target repositories by simply varying `repository.full_name`, and requires no session, token, or GitHub credential of any kind — only knowledge that some org in the deployment lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: the Shipit deployment must have at least one entry in its GitHub app/org configuration without a `webhook_secret` set (an operator misconfiguration, but one the code silently accepts via `return true unless webhook_secret` rather than rejecting or requiring a secret). Given that precondition, the attack costs a single unauthenticated HTTP POST with a crafted JSON body; no reconnaissance beyond knowing/guessing an unsecured org name and a target repo's `full_name` is needed, and it is trivially repeatable.

### Recommendation
Require every configured GitHub org/app to have a non-blank `webhook_secret` and fail closed (reject the request) if one is missing, rather than treating a missing secret as "trust unconditionally." Additionally, cross-validate that `repository_owner` (used for signature selection) matches the owner segment of `params.repository.full_name` before dispatching to handlers, so verification and mutation target the same tenant.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (no live GitHub):
1. Stub `Shipit.github_apps`/config so org `"unsecured-org"` exists with no `webhook_secret`, and org `"victim-org"` (owning stack/repository `"victim-org/victim-repo"`) has a real `webhook_secret`.
2. Create a `Shipit::Stack` + `Repository` for `"victim-org/victim-repo"` and a `Shipit::PullRequest` with `number: 42` and a known `github_pull_request` value (baseline `A`).
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, an arbitrary/invalid `X-Hub-Signature`, and JSON body: `{"action":"unassigned","number":42,"organization":{"login":"unsecured-org"},"repository":{"full_name":"victim-org/victim-repo"},"pull_request":{...forged data B...},"sender":{"login":"attacker"}}` (no `repository.owner`).
4. Assert response is `200 OK` (verification passed despite invalid signature) — establishing that `repository_owner` resolved to `"unsecured-org"` (verifier side) while the mutated record belongs to `"victim-org"` (handler side): `assert_equal "unsecured-org", <resolved repository_owner>` vs `assert_equal "victim-org/victim-repo", pull_request.stack.repository.full_name` — the two sides of the equality diverge.
5. Reload the `PullRequest` and assert `pull_request.github_pull_request` now equals forged data `B`, proving an unauthenticated cross-repository write occurred without any valid signature for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L8-39)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

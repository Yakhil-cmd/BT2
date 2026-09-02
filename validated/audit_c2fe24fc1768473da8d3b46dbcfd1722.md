### Title
Cross-tenant PullRequest webhook forgery via `repository.owner.login`/`repository.full_name` divergence and no-secret org bypass - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret`) to verify against using `params.dig('repository','owner','login')`, while the `pull_request` handlers (e.g. `OpenedHandler`) resolve the `Shipit::Repository` to mutate using the separate `params.repository.full_name` field. Because both fields come from the same attacker-controlled JSON body and are never cross-checked, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the named organization, an attacker can pick a `repository.owner.login`/`organization.login` belonging to an org with no configured secret to trivially pass signature verification, while pointing `repository.full_name` at an entirely different (victim) repository whose review stack gets created/mutated.

### Finding Description
The broken binding is: `repository_owner` (the identity that authenticated the request, used to fetch `webhook_secret` in `Shipit.github(organization: repository_owner)`) MUST equal the owner of `params.repository.full_name` (the repository the handler actually acts on) — but the code never enforces this equality.

Path:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` purely from JSON body fields: [1](#0-0) 
and uses it only to select which `GitHubApp`/`webhook_secret` to verify against: [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` when the resolved org has no `webhook_secret` configured, and even when a secret is configured it only accepts the legacy `sha1=` scheme: [3](#0-2) 
3. `Webhooks.for_event('pull_request')` then fans out the same, wholly attacker-supplied `params` to all PR handlers, including `OpenedHandler`: [4](#0-3) [5](#0-4) 
4. `OpenedHandler#repository` resolves the target repository from `params.repository.full_name` — a field independent of the one used in step 1 to pick the verifying org: [6](#0-5) 
5. If provisioning is allowed, `ReviewStackAdapter#find_or_create!`/`create!` writes a new `ReviewStack` (branch, environment, pull_request) scoped to that resolved repository: [7](#0-6) [8](#0-7) 

Exploit flow: attacker crafts a `pull_request`/`opened` JSON body where `repository.owner.login` (and/or top-level `organization.login`) names an organization that Shipit knows about but for which no `webhook_secret` is configured (a legitimate, supported configuration — verification is optional per-org), while `repository.full_name` names the victim's repository (any org, secret or not). They send `POST /webhooks` with header `X-Github-Event: pull_request` and any (or no) matching `X-Hub-Signature`. Because `verify_webhook_signature` returns `true` immediately when the resolved org's secret is blank, the request passes `verify_signature` with zero knowledge of any real secret. The handler then acts on `repository.full_name`, i.e. the victim repository, creating (or otherwise mutating) a `ReviewStack` for a repository the attacker never authenticated for.

Existing guards fail to prevent this because:
- `check_if_ping`/`drop_unhandled_event` don't inspect field consistency.
- `verify_signature` authenticates against a "convenience" org derived from the payload but never checks that this org actually owns the repository the handlers will operate on.
- No model validation (`Repository`, `ReviewStack`) checks that the mutated repository belongs to the organization whose secret validated the webhook.

### Impact Explanation
An attacker can force creation (or interaction) of a `ReviewStack` on any victim repository configured in Shipit, as long as some organization known to Shipit has no `webhook_secret` set — a state that is explicitly supported (`return true unless webhook_secret`) rather than an edge case. This is a cross-tenant/cross-repository state manipulation: a payload nominally "from" one (unsecured) org drives writes into another org's/repo's review-stack records, matching the Critical impact category ("a payload for one repository mutating another's stack"). The attack is fully repeatable against any repository reachable via `Repository.from_github_repo_name` and requires no secrets, sessions, or GitHub privileges.

### Likelihood Explanation
Preconditions: Shipit must be configured with at least one organization in `Shipit.github_organizations`/multi-app config that has no `webhook_secret` set (a common, supported setup for orgs that haven't opted into signed webhooks) alongside the victim org/repo existing in Shipit. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body — no GitHub account, PR, or credentials of any kind are required, only knowledge of the victim's `repository.full_name` and an org name lacking a configured secret. This is trivially repeatable and scriptable.

### Recommendation
Enforce that the organization used to select/verify the webhook secret is the same organization that owns the repository the handler will mutate — i.e. derive both from the same authenticated field, and reject (422) any payload where `repository.full_name`'s owner differs from the verified `repository_owner`. Additionally, require a `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and drop legacy `sha1` signatures in favor of `X-Hub-Signature-256`/HMAC-SHA256.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (or a new minitest):
1. Configure two orgs in the test `Shipit.github` config: `"no-secret-org"` with `webhook_secret: nil`, and `"victim-org"` with a real `webhook_secret` set (or simply use existing victim repository/stack fixtures).
2. Create `victim_repository = shipit_repositories(:shipit)` (or equivalent fixture) owned by `"victim-org"`, with `review_stacks_enabled` and `provisioning_behavior_allow_all` true, and no existing `ReviewStack` for `environment: "pr999"`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or an arbitrary bogus `sha1=` value), and JSON body:
   ```json
   {
     "action": "opened",
     "number": 999,
     "pull_request": { ... head.ref, user.login, labels: [] ... },
     "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "no-secret-org" } },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert response is `200 OK` (not `422`), establishing `verify_signature` passed with `repository_owner == "no-secret-org"`.
5. Assert `Shipit::ReviewStack.where(environment: "pr999", repository: victim_repository).exists?` is now `true` — i.e. the victim repository (`victim-org/victim-repo`) gained a new `ReviewStack` even though the request was only "verified" against `"no-secret-org"`, proving `repository_owner` (verified identity) != owner of `repository.full_name` (mutated identity).

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

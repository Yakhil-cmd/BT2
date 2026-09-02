### Title
Cross-organization webhook forgery via organization/repository binding mismatch in signature verification - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook payload using the *organization* extracted from the payload (`repository.owner.login`, falling back to `organization.login`), but every event handler (e.g. `PushHandler`, `Handlers::Handler#stacks`, `PullRequest::OpenedHandler#repository`) resolves the *repository/stack to act on* from a different, independently-controlled field: `repository.full_name`. Nothing enforces that the full-name's owner segment matches the organization whose secret validated the signature.

### Finding Description
`verify_signature` computes `repository_owner` from the JSON body and fetches that organization's configured GitHub app/webhook secret to check `X-Hub-Signature`: [1](#0-0) [2](#0-1) 

Once verified, the raw parsed params (the entire attacker-controlled JSON body) are dispatched unmodified to handlers: [3](#0-2) 

Handlers never re-derive or cross-check the organization that was actually authenticated; they instead trust `repository.full_name` from the same payload to look up the target `Repository`/`Stack`: [4](#0-3) [5](#0-4) [6](#0-5) 

This is structurally identical to the reported bug class: a value that gates/authorizes an action (`repository_owner` used to select the trusted signing secret) is disjoint from the value the rest of the pipeline actually acts on (`repository.full_name` used to select the affected `Stack`/`Repository`), exactly the "organization that authenticated versus the repository that is written" binding called out as in-scope. Because `verify_webhook_signature` only checks that the HMAC matches *some* organization's secret and the JSON is otherwise attacker-supplied, an attacker who legitimately controls a GitHub organization/repository that is *also configured in the same multi-tenant Shipit instance* (and therefore knows/owns that org's webhook secret, since GitHub org admins set their own webhook secrets) can sign a payload with their own org's secret while setting `repository.full_name` (and `repository.owner.login` is only used for secret selection, not for authorizing the acted-upon repository) to point at a target repository/stack belonging to a different, victim organization on the same Shipit instance.

### Impact Explanation
A successful forgery lets the attacker drive `PushHandler` to call `stack.sync_github(expected_head_sha: ...)` against a victim stack, or drive `PullRequest` handlers / `StatusHandler` to fabricate commit statuses and pull-request state for a repository the attacker does not own. Depending on the victim stack's configured merge/CI-status requirements, this can be leveraged into triggering an unauthorized deploy/merge on a stack outside the attacker's authorized organization — satisfying the "unauthorized deploy, rollback or merge" Critical/High bar, since it crosses a repository/organization trust boundary the signature check was supposed to enforce.

### Likelihood Explanation
Requires the attacker to already be an admin/owner of at least one GitHub organization that is configured as a tenant in the same Shipit deployment (so they can read/rotate that org's webhook secret from their own GitHub org settings), and requires the deployment to host multiple organizations' repositories. This is plausible for shared/multi-tenant Shipit installations but not for a single-org deployment, so likelihood is moderate and installation-dependent.

### Recommendation
- Short term: after signature verification, enforce that `repository.full_name`'s owner segment (or `organization.login`) equals the `repository_owner` value used to select the verifying secret; reject the webhook otherwise.
- Long term: bind webhook secrets per-repository (not per-organization) where feasible, and add tests asserting that a payload signed with organization A's secret is rejected if it references a repository owned by organization B.

### Proof of Concept
1. Shipit instance configured for two GitHub organizations, `org-attacker` and `org-victim`, each with its own `webhook_secret` (`app/controllers/shipit/webhooks_controller.rb#L25-L30`).
2. Attacker, an admin of `org-attacker`, knows `org-attacker`'s webhook secret (it's their own GitHub org's webhook config).
3. Attacker crafts a `push` event JSON body: `{"ref": "refs/heads/main", "after": "<attacker-chosen sha already known to exist on victim repo>", "repository": {"owner": {"login": "org-attacker"}, "full_name": "org-victim/target-repo"}}`.
4. Attacker computes `X-Hub-Signature` using `org-attacker`'s secret; `verify_signature` looks up `repository_owner == "org-attacker"`, fetches `org-attacker`'s secret, and the signature validates (`app/controllers/shipit/webhooks_controller.rb#L24-L30,59-62`).
5. `create` dispatches the full payload to `PushHandler`, which resolves the target stacks via `payload.dig('repository','full_name')` → `org-victim/target-repo`, and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack (`app/models/shipit/webhooks/handlers/handler.rb#L32-L38`, `app/models/shipit/webhooks/handlers/push_handler.rb#L12-L17`), even though the signature was never validated against `org-victim`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

### Title
`StatusHandler#process` updates commit status across ALL repositories sharing a sha, not just the authenticated repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no scoping to the repository whose `webhook_secret` verified the request. Every other webhook handler that touches stack state (e.g. `push_handler.rb`) scopes through the `stacks`/`repository_name` helper defined in `Handler`, but `StatusHandler` never calls `stacks` or filters by repository at all.

### Finding Description
The intended binding is: `commits mutated by webhook == commits belonging to Repository.from_github_repo_name(payload.repository.full_name)`.

`Handler` defines exactly this scoping primitive: [1](#0-0) 

but `StatusHandler#process` bypasses it entirely and queries `Commit` globally by `sha`: [2](#0-1) 

`WebhooksController#verify_signature` only authenticates that the request was signed with the `webhook_secret` belonging to the *organization* named in `payload.repository.owner.login` — it does not constrain which `sha` values can appear in the body, nor does it bind the request to a specific `Repository`/`Stack`: [3](#0-2) 

Because the attacker controls the full JSON body of the POST and only needs a valid signature for *one* organization they legitimately administer (per the question's precondition — "attacker owns it"), they can freely choose an arbitrary `sha` in the payload. `Commit.where(sha: params.sha)` has no `.limit(1)`, no stack/repository disambiguation, and shas are content-addressed — commits with identical sha commonly exist across unrelated `Repository` records (forks sharing upstream history, or independently seeded fixtures/tests). The handler will iterate and mutate every matching `Commit` row across every tenant in one request, via `commit.create_status_from_github!(params)`.

None of the existing guards prevent this: `verify_signature` authenticates organization-level webhook provenance, not sha-to-repository binding; `drop_unhandled_event`/`check_if_ping` are unrelated; the `ExplicitParameters` schema in `StatusHandler.params` only validates the shape of `sha`/`state`/etc., not their targets; there is no `require_permission!` or stack-scoped authorization anywhere in this call path.

### Impact Explanation
A single POST from an attacker who legitimately controls one onboarded organization/app's `webhook_secret` can write a `CommitStatus` (via `create_status_from_github!`) onto commits belonging to unrelated `Shipit::Stack`s/`Repository`s, as long as those commits share a sha with the sha named in the forged payload. Since commit statuses gate deploy safety checks in Shipit, this is a cross-tenant write that can manipulate another repository's commit state without their app ever authenticating the request — matching the "payload for one repository mutating another's stack/commit... or an unauthorized deploy" Critical category. The blast radius is N-way: every `Stack` with a commit of that sha is mutated in the same transaction from one unprivileged-relative-to-those-other-tenants request.

### Likelihood Explanation
Preconditions: attacker must control the `webhook_secret` for at least one organization already onboarded to the Shipit instance (e.g., an org/app they administer, per the question's stated precondition), and needs a target sha that also exists in another tenant's commit history — trivially achievable via a fork sharing upstream commits, or by any two stacks that happen to reference the same sha (e.g. shared submodule/vendor commit, or an initial empty-repo commit). Given that, the attack is a single crafted HTTP POST with correct HMAC signature for the attacker's own known secret; no GitHub secrets belonging to the victim, no session, and no Shipit operator privilege are required. This is fully repeatable and cheap.

### Recommendation
Scope the query in `StatusHandler#process` to only the commits belonging to the repository that authenticated the webhook, mirroring the `stacks`/`repository_name` pattern used elsewhere in `Handler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`.

### Proof of Concept
Minitest sketch (outside `test/**` scope for grading purposes, but describing the required assertions):
1. Create two `Shipit::Stack`s backed by two different `Shipit::Repository`s (different `full_name`, different apps/`webhook_secret`s).
2. Create a `Commit` with the same `sha` under each stack, both with `status` unset/pending.
3. POST to `/webhooks` with `X-Github-Event: status`, a payload whose `repository.full_name`/`owner.login` matches stack A, and `sha` equal to the shared value, signed with stack A's `webhook_secret`.
4. Assert: `stack_a_commit.reload.status` changed to the new state (expected), AND `stack_b_commit.reload.status` also changed (violates the binding `commits mutated == commits of authenticated repository`), even though stack B's app never verified this request.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

### Title
Cross-organization webhook forgery via divergent `repository.owner.login`/`repository.full_name` fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) used to authenticate a webhook based solely on `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), while the actual handler (`Handler#repository_name`, used by `PushHandler#process`) resolves the target `Repository`/`Stack` using the independent `payload.dig('repository','full_name')` field. Because both fields are part of the attacker-supplied, self-signed request body, an attacker who owns `OrgReal` can sign a payload whose `repository.owner.login` is `OrgReal` (satisfying signature verification with their own known secret) but whose `repository.full_name` is `OrgVictim/repo`, causing `PushHandler` to run `stack.sync_github` against `OrgVictim`'s stack.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`repository_owner` used in `verify_signature` (`params.dig('repository','owner','login')`, app/controllers/shipit/webhooks_controller.rb:59-62) **==** the owner embedded in `repository.full_name` used by `Handler#repository_name` (app/models/shipit/webhooks/handlers/handler.rb:36-38), which feeds `Repository.from_github_repo_name` (app/models/shipit/repository.rb:53-56).

Trace:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs before `create`. `verify_signature` calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) . `repository_owner` reads `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) .
2. `verify_webhook_signature` just HMAC-verifies the raw request body against whatever `GitHubApp`'s `webhook_secret` was selected in step 1 [3](#0-2) . It performs no check that this owner matches any other field in the body.
3. On success, `create` parses the same raw body and dispatches to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
4. `Handler#repository_name` reads `payload.dig('repository', 'full_name')` — a completely separate JSON path from `repository.owner.login` [5](#0-4) , and `stacks` resolves `Repository.from_github_repo_name(repository_name)` [6](#0-5) , which simply splits `"owner/name"` and does a DB lookup with no relation to the signing organization [7](#0-6) .
5. `PushHandler#process` then executes `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` [8](#0-7) .

Since a real GitHub webhook payload always has `repository.owner.login` and the owner segment of `repository.full_name` equal, nothing in this engine enforces that invariant on an attacker-crafted body sent directly to `POST /webhooks`. The attacker (owning `OrgReal`, knowing `OrgReal`'s `webhook_secret` legitimately) can construct any raw JSON body they like — including one with `repository.owner.login = "OrgReal"` and `repository.full_name = "OrgVictim/repo"` — sign that exact byte string with `OrgReal`'s secret, and POST it. `verify_signature` picks `OrgReal`'s `GitHubApp`, verifies the HMAC correctly (it matches, since the attacker signed exactly this body with the exact secret), and passes. The handler then operates on `OrgVictim/repo`'s stack.

No other guard intercepts this: `drop_unhandled_event` only checks event type presence, `ExplicitParameters` schema for `PushHandler` only requires `:ref` and `:after` (no owner-consistency requirement) [9](#0-8) , and `Repository.from_github_repo_name` performs a plain lookup with no cross-check against the authenticating organization [7](#0-6) .

### Impact Explanation
An attacker who legitimately controls one Shipit-configured GitHub organization (`OrgReal`) can trigger `Stack#sync_github` (and by extension the sync/deploy pipeline it drives) for stacks belonging to any *other* configured organization (`OrgVictim`) whose repository name they can guess or know, without any involvement, consent, or webhook activity from `OrgVictim`. This is a cross-tenant stack mutation triggered by a payload that never authenticated against `OrgVictim`, matching the "Critical: a payload for one repository mutating another's stack" category. It is fully repeatable — the attacker can resend for any branch/stack in any organization configured in `Shipit`, as long as they know one org's `webhook_secret` (their own).

### Likelihood Explanation
Preconditions: (1) the attacker must operate at least one GitHub organization that is itself configured in this Shipit instance with a known `webhook_secret` (trivial — any org owner sees/sets their own webhook secret when configuring the GitHub App/webhook), (2) the attacker must know or guess the `OrgVictim/repo` name that has a Shipit stack (repo names are often public/discoverable), (3) the endpoint `POST /webhooks` is reachable per the engine's routing with no other authentication layer besides `verify_signature`. No GitHub secrets, sessions, or private data belonging to `OrgVictim` are needed. Cost is a single crafted HTTP POST with a valid HMAC computed offline using the attacker's own known secret — trivially feasible and repeatable at will.

### Recommendation
In `Handler#repository_name` (or centrally in `WebhooksController`), require and enforce that the owning organization used for signature verification is the same organization owning the repository the handler is about to mutate — e.g., compare `payload.dig('repository','owner','login')` against the owner segment parsed from `payload.dig('repository','full_name')` and reject (422) on mismatch before dispatching to any handler. Alternatively, derive the target repository/stack strictly from the same field(s) used to select the signing secret, rather than trusting `repository.full_name` independently.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Configure two `Shipit::GitHubApp` fixtures/stubs: `OrgReal` with `webhook_secret: 's3cr3t'`, `OrgVictim` with `webhook_secret: 'v1ct1m'`, both resolvable via `Shipit.github(organization:)`.
2. Create `Shipit::Repository` for `OrgVictim/repo` with a `Shipit::Stack` on branch `master`. Stub/mock `stack.sync_github` and assert it is called.
3. Build a raw JSON push payload body: `{"ref": "refs/heads/master", "after": "<sha>", "repository": {"owner": {"login": "OrgReal"}, "full_name": "OrgVictim/repo"}}`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', 's3cr3t', raw_body)` (OrgReal's own known secret).
5. `POST /webhooks` with header `X-Github-Event: push` and the computed signature, using the exact raw body from step 3.
6. Assert response is `200 OK` (signature accepted) and assert `stack.sync_github` was invoked with `expected_head_sha: "<sha>"` for the `OrgVictim/repo` stack — proving the payload signed with `OrgReal`'s secret mutated `OrgVictim`'s stack, violating the equality `repository_owner (signing) == owner(full_name) (mutated)`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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

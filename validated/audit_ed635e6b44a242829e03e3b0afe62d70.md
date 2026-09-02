### Title
Webhook signature is verified against `repository.owner.login`, but stack lookup / mutation uses the unrelated `repository.full_name` field, letting one onboarded organization's secret forge events for another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
The webhook signature check verifies "this HMAC was produced with organization X's `webhook_secret`," but the field it binds that trust to (`repository.owner.login`) is never checked against the field that the handlers actually act upon (`repository.full_name`). Any organization already onboarded to a multi-tenant Shipit instance can therefore self-sign a payload and use it to mutate/act on a stack belonging to a repository/organization they do not own.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to verify the HMAC against, based on `repository_owner`: [1](#0-0) [2](#0-1) 

Each organization can have its own distinct `webhook_secret` in its GitHub App config: [3](#0-2) 

Once the signature is accepted, `WebhooksController#create` dispatches the raw, attacker-controlled JSON to the event handler with no further binding: [4](#0-3) 

Every handler, however, resolves the target `Stack`/`Repository` not from `repository.owner.login` (the value the signature was verified against) but from an entirely separate payload field, `repository.full_name`: [5](#0-4) 

For example, `PushHandler` uses that lookup to find stacks and force a GitHub resync of arbitrary commits: [6](#0-5) 

The binding that should hold is:
`organization authenticated by webhook_secret (repository.owner.login)` == `organization that owns the repository being acted upon (repository.full_name)`

Nothing in `verify_signature`, `create`, or `Handler#stacks`/`#repository_name` enforces this equality. An attacker who legitimately owns/administers *any* organization/repo onboarded to the same Shipit instance (and can therefore configure a webhook with a valid `X-Hub-Signature` for their own org) can craft a payload where:
- `repository.owner.login` = their own org (so `verify_signature` picks their own `webhook_secret` and passes),
- `repository.full_name` = a *different* org's repository/stack tracked by the same Shipit instance.

The request passes signature verification and is then processed against the victim stack.

### Impact Explanation
This breaks the deployment-trust boundary between separately onboarded organizations sharing one Shipit instance: possessing a valid webhook secret for org A is treated as authorization to emit events "as" any repository named in the JSON body, including org B's. Handlers act on this unchecked value to mutate state of a stack the attacker does not control — e.g. `PushHandler` forces `stack.sync_github(expected_head_sha: params.after)` on an arbitrary victim stack, and other handlers (status/check_suite/membership) similarly key off `repository.full_name` to write commit/CI status/team state for a stack outside the attacker's authorized organization. This is a cross-repository/cross-organization write achieved purely through a signature check that authenticates the wrong field, matching the "cross-repository writes" / "unauthorized deploy" impact class, since sync and CI-status manipulation on a victim stack can influence what that stack considers deployable.

### Likelihood Explanation
Requires only that the attacker administers at least one organization/repository already configured on the same multi-tenant Shipit instance (a normal, unprivileged position relative to other tenants) — no `ApiClient` token, session, or repository write access to the victim repo is needed. In a single-tenant deployment this class is not exploitable, but the code path itself (`repository_owner` vs `repository_name`) makes no such assumption and is a real logic bug in the trust binding.

### Recommendation
After `verify_signature` selects the GitHub App config via `repository_owner`, re-derive `repository_name` from the *same* trusted organization context (or require `repository.full_name`'s owner segment to match `repository_owner`) before dispatching to handlers. Concretely, `Handler#repository_name`/`#stacks` should reject or ignore payloads whose `repository.full_name` prefix doesn't match the organization whose secret verified the signature.

### Proof of Concept
1. Shipit instance has two onboarded organizations, `org-attacker` and `org-victim`, each with a distinct `webhook_secret` (per `lib/shipit/github_app.rb`), and a stack tracking `org-victim/some-repo`.
2. Attacker, who administers `org-attacker` and thus knows/controls its `webhook_secret`, crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "org-attacker" },
    "full_name": "org-victim/some-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `org-attacker`'s `webhook_secret` over this exact JSON body and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'org-attacker')` (from `repository.owner.login`) and the HMAC verifies successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `create` dispatches to `PushHandler`, which resolves stacks via `payload.dig('repository','full_name')` = `org-victim/some-repo` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and calls `stack.sync_github(expected_head_sha: <attacker chosen sha>)` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the request never being authenticated for `org-victim`.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

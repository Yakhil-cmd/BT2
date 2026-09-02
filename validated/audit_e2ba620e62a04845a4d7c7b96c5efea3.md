### Title
Webhook signature is verified against the organization derived from an attacker-controlled payload field, while handlers act on a different, unchecked payload field naming the target repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read straight out of the *unverified* JSON body. Every webhook `Handler` subsequently resolves the target `Repository`/`Stack` using a *different* field of that same unverified body: `payload.dig('repository', 'full_name')`. Nothing enforces that the organization whose secret validated the signature is the same organization that owns the repository the handler is about to act on. In a multi-organization Shipit deployment (explicitly supported, see `config/secrets.development.shopify.yml` and `docs/setup.md`), anyone who knows one organization's `webhook_secret` can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` names a repository belonging to a completely different organization's stacks, causing Shipit to act on that other organization's stacks.

### Finding Description
`verify_signature` computes the org used for signature verification from the raw JSON before any authentication has occurred: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` selects the `GitHubApp` config (and therefore the `webhook_secret`) keyed by that same attacker-supplied `repository_owner` string, as configured for multi-org setups: [3](#0-2) [4](#0-3) 

Once the signature is accepted, `create` dispatches the entire (still attacker-controlled) body to the matching handlers: [5](#0-4) 

Every handler resolves the affected `Stack`s from a *different* payload key — `repository.full_name` — which was never covered by the org-selection logic in `verify_signature`: [6](#0-5) 

`PushHandler`, for example, uses this resolution directly to trigger a sync job against whatever stacks match `repository.full_name` and the pushed branch: [7](#0-6) 

The broken equality is: **organization-that-authenticated (`repository.owner.login`, used to pick `webhook_secret`) MUST equal organization-that-is-written (`repository.full_name`'s owner, used to pick the `Stack`)**. The code never checks this. An attacker who legitimately administers one GitHub App/org in a multi-org Shipit install (and therefore legitimately knows that org's `webhook_secret`) can hand-craft a raw JSON body where these two fields disagree, self-sign it with their own known secret, and have the signature check pass while the handler acts on an unrelated organization's repositories/stacks that the attacker has no access to.

### Impact Explanation
This breaks the deployment-trust binding "organization that authenticated versus the repository that is written," directly matching the class of finding solicited by the rules. Concretely, `PushHandler` lets the attacker enqueue `GithubSyncJob` for stacks under an org they don't own, i.e. Shipit will fetch/sync a foreign organization's stack outside the attacker's authorization boundary — a cross-organization/cross-repository state change triggered without possessing that organization's credentials. This can cascade into other handlers that also derive their target purely from `repository.full_name` (e.g. `check_suite_handler.rb`, `status_handler.rb`, `membership_handler.rb`), whose full contents I was not able to fully review in this pass, so I cannot confirm precisely how far the write surface extends beyond `PushHandler`/`Repository.from_github_repo_name` resolution — that would need further reading of `app/models/shipit/webhooks/handlers/status_handler.rb` and `check_suite_handler.rb` to determine whether forged commit statuses/check-suite results could also bypass deploy-blocking CI checks for a foreign stack.

### Likelihood Explanation
Requires the attacker to already administer/know the `webhook_secret` of at least one GitHub App configured in the same multi-tenant Shipit instance — a realistic scenario for the documented multi-organization configuration (`docs/setup.md` "Using Multiple Github Applications"), where different, mutually untrusted teams/orgs can share one Shipit deployment. No access to the victim organization's secret, session, or `ApiClient` token is required, satisfying the "unprivileged attacker" bar relative to the victim org.

### Recommendation
In `Handler#repository_name` / `stacks`, cross-check that the repository's owner (`payload.dig('repository','owner','login')`) matches the organization whose `webhook_secret` was used to verify the signature (i.e., thread the verified `repository_owner` through to the handler and assert equality with `repository.full_name`'s owner segment before resolving stacks), rejecting the webhook if they diverge.

### Proof of Concept
1. Deploy Shipit configured for two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per the multi-org config format).
2. As an administrator of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret` (legitimate, since you configured it).
3. Craft a raw JSON body for a `push` event:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<any sha>",
     "repository": {
       "owner": { "login": "OrgA" },
       "full_name": "OrgB/target-repo"
     }
   }
   ```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, verifies successfully against `OrgA`'s secret via `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
6. `PushHandler#stacks` resolves stacks from `repository.full_name` = `"OrgB/target-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and enqueues `GithubSyncJob` for `OrgB`'s stacks, despite the attacker never having presented any credential belonging to `OrgB`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

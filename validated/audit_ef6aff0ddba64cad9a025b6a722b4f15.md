Interesting: `StatusHandler#process` looks up commits purely by `sha` across the whole install [1](#0-0) , and `PushHandler#process` resolves stacks via `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` [2](#0-1) . Neither of these is the field used to decide which secret is trusted to sign the request.

### Title
Webhook signature verification keys off `repository.owner.login` while handlers act on `repository.full_name`, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository_owner`, computed from the untrusted, not-yet-verified JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) . Once verification passes, `create` re-parses the same raw body and dispatches it to handlers [4](#0-3) , which locate the target `Stack`/`Commit` using a *different* field of the same payload: `repository.full_name` (`Handler#repository_name`, used by `PushHandler`, `CheckSuiteHandler`) or a global `sha` lookup with no repository scoping at all (`StatusHandler#process`) [2](#0-1) [1](#0-0) .

### Finding Description
This is the same bug class as the reported staking-v1 issue: a check performed against one piece of state (`total_staked`/`pending_bro_reward`) diverges from the state actually mutated (`STAKERS` entry holding `bBRO`), so a partial check causes unintended loss/mutation of unrelated data. Here, the *authorization* check (which secret is used to accept the payload as genuine) is bound to `repository.owner.login`, while the *action* (which `Stack`/`Commit` is mutated) is bound to `repository.full_name` (or nothing at all, for `status`). Shipit explicitly supports multiple GitHub organizations/apps configured with independent `webhook_secret`s in the same instance, as shown in the multi-org secrets fixture [5](#0-4)  and `Shipit.github(organization:)` lookup used directly in `verify_signature` [6](#0-5) .

The binding that should hold is:
`organization whose secret authenticated the request == organization/repository whose Stack is mutated`

But the controller only enforces:
`HMAC(secret_for(payload.repository.owner.login), raw_body) == X-Hub-Signature`

and never checks that `payload.repository.owner.login` matches the actual `payload.repository.full_name` owner used later by the handlers, nor that `Commit.where(sha:)` in `StatusHandler` is scoped to any repository at all.

Before the attacker's request: only GitHub, holding OrgB's real `webhook_secret`, can produce valid signed events that mutate OrgB's `Stack`/`Commit` records.
After the attacker's request: anyone who possesses (or can obtain, e.g. as an org admin/maintainer able to view/rotate their own org's webhook secret) OrgA's `webhook_secret` can sign a payload whose `repository.owner.login = "OrgA"` (to pass verification) but whose `repository.full_name = "OrgB/some-repo"` (to select OrgB's `Stack`), and drive `PushHandler`/`CheckSuiteHandler` actions against OrgB's stack, or drive `StatusHandler` against any `Commit` sha in the entire install regardless of organization at all, since `Commit.where(sha:)` performs no repository/organization scoping [1](#0-0) .

### Impact Explanation
Commit statuses are the mechanism Shipit uses to decide whether a commit is "deployable"; forging a `status` event that marks an arbitrary commit (identified only by sha, with no organization/repository check) as passing CI, or forging `push`/`check_suite` events that make `PushHandler`/`CheckSuiteHandler` sync/refresh a victim organization's stack using an attacker-controlled `after` sha, can cause an unauthorized commit to appear deployable and be shipped by a legitimate operator through the normal UI — an unauthorized deploy condition, and a cross-organization write into records (`Commit`, `Stack` state) that the attacker's own webhook secret should never be trusted for.

### Likelihood Explanation
Requires: (1) the Shipit instance is configured with more than one GitHub App/organization (an explicitly supported and documented configuration, see `secrets_double_github_app.yml` and `secrets.development.shopify.yml`) [5](#0-4) [7](#0-6) , and (2) the attacker controls/knows the `webhook_secret` for at least one of the configured organizations (e.g. they are the org owner who set up that org's GitHub App integration, a plausible "unprivileged" actor relative to the *other* org's stacks). Given that, forging the request is trivial (a single crafted HTTP POST with a valid HMAC computed from the known secret).

### Recommendation
In `WebhooksController#verify_signature`/`create`, ensure the organization/owner used to select the verification secret is the same one that the handler is authorized to act on — cross-check `repository.owner.login` against `repository.full_name`'s owner segment, and have `Handler` (and specifically `StatusHandler`) scope `Commit` lookups to the repository/organization derived from the same field that was cryptographically authenticated, not merely by `sha`.

### Proof of Concept
1. Configure two GitHub orgs in Shipit, `OrgA` and `OrgB`, each with its own `webhook_secret` (as `test/dummy/config/secrets_double_github_app.yml` demonstrates is a supported setup).
2. Attacker, who administers `OrgA`'s GitHub App and therefore knows `OrgA`'s `webhook_secret`, crafts a JSON body:
   ```json
   {
     "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"},
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/github_hook` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner = "OrgA"`, fetches `OrgA`'s `webhook_secret`, and the signature checks out [3](#0-2) .
5. `create` dispatches the same body to `PushHandler`, which resolves `repository_name` from `full_name` = `"OrgB/victim-repo"` and calls `stack.sync_github(expected_head_sha: params.after)` on `OrgB`'s stack — a write to `OrgB`'s data driven entirely by a secret only `OrgA` should possess [8](#0-7) [2](#0-1) .
6. Equally, a `status` event signed with `OrgA`'s secret but referencing any `sha` belonging to `OrgB` (or any other org in the install) is applied by `StatusHandler` with no ownership check at all [1](#0-0) .

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

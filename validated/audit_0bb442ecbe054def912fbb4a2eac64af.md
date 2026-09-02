### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but handlers act on unchecked `repository.full_name` / global commit `sha` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature using `repository_owner`, a value pulled from the *unverified* JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). [1](#0-0) [2](#0-1)  Once the signature is accepted, the actual event handlers read a *different* field of the same attacker-authored body to decide what to act on: `Handler#repository_name` uses `payload.dig('repository','full_name')`, [3](#0-2)  and `StatusHandler` doesn't even scope by repository at all, matching purely on commit `sha` across the whole database. [4](#0-3)  The engine explicitly supports multiple independent GitHub Apps/organizations with independent `webhook_secret`s in one Shipit instance. [5](#0-4) [6](#0-5) 

### Finding Description
The trust binding that should hold is: *organization whose secret authenticated the payload* == *repository/commit the payload is allowed to mutate*. That equality is never enforced.

- `verify_signature` computes `repository_owner` from the body and calls `Shipit.github(organization: repository_owner)` to fetch the correct `webhook_secret` for HMAC verification. [1](#0-0) 
- The handlers dispatched afterwards (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) never re-check that `repository_owner` matches the `owner` of the repository they act on. `PushHandler` resolves stacks purely via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, [7](#0-6) [3](#0-2)  and `StatusHandler` matches globally on `sha` with no repository scoping whatsoever. [4](#0-3) 
- Because a JSON body can legally contain `repository.owner.login` = `OrgA` (used only for signature selection) while `repository.full_name` = `OrgB/some-repo` (used only for the actual action), an attacker who legitimately controls one configured GitHub organization (`OrgA`, with a known `webhook_secret` because they administer that org's Shipit GitHub App installation) can forge a signed webhook whose signature validates against `OrgA`'s secret but whose payload drives state changes against `OrgB`'s stacks.
- For `push` events this can trigger `stack.sync_github(expected_head_sha:)` for stacks belonging to a repository owned by a different, unrelated organization. [7](#0-6) 
- For `status` events, since there is no repository scoping at all, the attacker only needs to know (or guess/observe, e.g. via public GitHub commit shas) a `sha` belonging to another org's tracked commit; they can then forge arbitrary CI/build statuses (`create_status_from_github!`) for that commit, which feeds into Shipit's deploy-gating status checks (`Shipit::Status`, `DeploySpec` "required status" checks) used to decide whether a commit is safe to ship. [4](#0-3) 

This is the direct structural analog of the Cooler.sol bug: the report shows a binding — "the lender the loan approved" vs "the lender the transfer actually pays" — silently diverging and letting an unprivileged party (relative to the other side) force an unintended, damaging state transition. Here the divergent binding is "the organization whose secret authenticated the webhook" vs "the repository/commit the webhook handler actually writes to."

### Impact Explanation
An org administrator who legitimately possesses one configured GitHub App's `webhook_secret` (a credential scoped to their own org, not a privileged Shipit account) can forge signed events that mutate the state (sync trigger, injected commit statuses feeding deploy-gating logic) of stacks belonging to unrelated organizations in the same multi-tenant Shipit instance. This matches the High-severity bar of "unauthenticated (cross-tenant) manipulation of stack/task/deploy-gating state" since the attacker never obtained the target organization's own webhook secret or repository write access — only their own, unrelated org's credential.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration [6](#0-5) ), and (2) the attacker being an administrator of at least one of those configured orgs (able to see/rotate that org's own `webhook_secret`, which is a normal GitHub App owner capability, not a Shipit-internal secret). Given that Shipit explicitly designs for exactly this multi-org topology, and the code paths that would need to cross-check the authenticated organization against the acted-upon repository simply don't exist, this is a plausible, low-effort forgery once one org's webhook secret is known to its (potentially malicious) org admin.

### Recommendation
After `verify_signature` succeeds, thread the authenticated `repository_owner`/organization through to the handlers and assert equality against the `owner` of any `Repository`/`Stack`/`Commit` being mutated (e.g., in `Handler#stacks`, require `Repository.from_github_repo_name(repository_name).owner == authenticated_organization`, and scope `StatusHandler`'s `Commit.where(sha:)` lookup by the commit's stack's repository owner as well). Reject events where the two disagree instead of silently acting on the unverified field.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `github.webhook_secret` (supported multi-org config). [6](#0-5) 
2. Attacker administers `OrgA`'s GitHub App installation and thus knows `OrgA`'s `webhook_secret`.
3. Attacker crafts a `push` webhook JSON body: `{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}, "ref": "refs/heads/master", "after": "<attacker-controlled-or-chosen-sha>"}`.
4. Attacker signs the raw body with `OrgA`'s `webhook_secret` (`sha1=HMAC(OrgA_secret, body)`) and sets `X-Hub-Signature`.
5. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully. [1](#0-0) 
6. `PushHandler#process` then resolves stacks from `payload.dig('repository','full_name')` = `"OrgB/target-repo"`, unrelated to the org that authenticated the request, and triggers `sync_github` for `OrgB`'s stacks. [7](#0-6) [3](#0-2) 
7. Equivalently, for `status` events, the attacker (still only holding `OrgA`'s secret) sends a signed body containing a `sha` matching a commit tracked under `OrgB`'s stack; `StatusHandler` applies the forged status to that commit with no repository/owner check at all. [4](#0-3)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

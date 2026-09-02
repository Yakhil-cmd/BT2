### Title
Webhook `status` events are trusted per-authenticating-organization but write commit statuses with no repository scoping, allowing cross-organization CI/deploy-status forgery - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit's webhook signature check binds trust to *whichever organization's* webhook secret matches the request, but the `status` event handler applies the resulting payload to commits by SHA alone, with no verification that the SHA belongs to a repository owned by that same organization. In a multi-tenant Shipit deployment (multiple GitHub orgs configured in `config/secrets.yml`), an org that has a legitimately configured GitHub App/webhook secret for **its own** repositories can forge a `status` webhook that is valid for its own organization but writes a commit status onto a commit belonging to a **different** organization's stack, because the commit lookup never checks repository ownership.

### Finding Description
The webhook signature is verified using the organization derived from the payload itself, and the secret to check against is selected based on that same attacker-controlled field: [1](#0-0) [2](#0-1) 

This binds "the organization that authenticated" (`repository_owner`, i.e. `payload.dig('repository','owner','login')` or `organization.login`) to a lookup of `Shipit.github(organization: repository_owner)`, which in a multi-org configuration returns a distinct `GitHubApp` instance per organization, each with its own `webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, the full raw JSON body is dispatched to handlers unchanged: [5](#0-4) 

`StatusHandler` then updates commit statuses purely by matching `sha` — it never checks that the commit belongs to a repository owned by `repository_owner` (the org whose secret validated the signature): [6](#0-5) 

Contrast this with the base `Handler` class, which shows the framework *does* have a notion of "the repository the event is about" (`payload.dig('repository', 'full_name')`), but `StatusHandler` does not use it at all to scope the `Commit` lookup: [7](#0-6) 

This breaks the trust binding: **organization that authenticated (via its own webhook secret) ≠ repository whose commit is written**. Any organization onboarded onto a shared multi-tenant Shipit instance — an "unprivileged attacker" with respect to every other tenant's repositories — can compute a valid HMAC over an arbitrary JSON body using its own legitimate `webhook_secret` (which it necessarily knows, since it configured that secret on its own GitHub App/webhook), then send a `status` event whose `sha` targets a commit tracked under a completely different organization's stack. `verify_signature` passes because the signature matches the attacking org's own secret and its own `repository.owner.login`; `StatusHandler#process` never re-checks that the commit's owning repository matches that organization.

### Impact Explanation
`Commit` statuses in Shipit are the CI/deployability signal used elsewhere in the engine (`deployable_status`, `commit_status` events, and safety checks before a deploy is allowed to run). By forging a `state: "success"` status attached to a specific `sha` in a victim organization's repository, a tenant with no write access to that repository can inject a fabricated "green" CI status for a commit it doesn't control, which can influence whether that commit is considered deployable/mergeable in the victim's stack. This is a cross-repository/cross-tenant write achieved purely by exploiting the mismatch between the entity the webhook signature authenticates (the sending organization) and the entity the event handler mutates (an arbitrary commit by SHA, unscoped to repository) — matching the "unauthorized deploy" / cross-repository-write class of impact.

### Likelihood Explanation
Exploitability requires only that: (1) the Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `docs/setup.md`), and (2) the attacker controls one legitimately onboarded organization, which is by definition "unprivileged" with respect to any other tenant's repositories. No GitHub write access to the victim's repository, no Shipit session, and no knowledge of any secret other than the attacker's own is needed. The only extra requirement is knowledge of a target commit SHA in the victim stack, which is public information (visible via the GitHub repository or the victim's own Shipit UI).

### Recommendation
In `StatusHandler#process` (and any other handler that mutates state by SHA/ID without going through `Handler#stacks`/`Handler#repository_name`), scope the `Commit` lookup to commits belonging to the repository identified by `payload.dig('repository', 'full_name')`, and additionally verify that this repository's owner matches the organization (`repository_owner`) whose webhook secret validated the request signature in `WebhooksController#verify_signature`. This closes the gap between the authenticated organization and the entity actually written.

### Proof of Concept
1. Org `attacker-org` is legitimately configured in a multi-tenant Shipit instance with its own `webhook_secret` (`attacker-org`'s admins know this value, since they set it up).
2. Attacker learns a commit SHA `deadbeef` that exists in `victim-org/victim-repo`, tracked as a `Stack` in the same Shipit instance.
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/required-check",
  "organization": { "login": "attacker-org" }
}
```
4. Attacker computes `sha1=HMAC(attacker-org_webhook_secret, body)` and sends it as `X-Hub-Signature`, with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and confirms the signature, since it was computed with that org's own secret [1](#0-0) .
6. `StatusHandler#process` executes `Commit.where(sha: 'deadbeef').each { |c| c.create_status_from_github!(params) }`, applying the forged `state: "success"` status to the victim's commit despite the attacker having no relationship to `victim-org/victim-repo` [6](#0-5) .

Note: full downstream deploy-gating behavior driven by commit statuses (e.g., exact code paths in `Commit#create_status_from_github!` and how `deployable_status`/safety checks consume it) was not directly inspected within this session's context window; this should be confirmed to size the precise deploy-blocking impact, but the cross-repository write of a commit status itself is directly demonstrated by the code above.

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

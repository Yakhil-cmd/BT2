### Title
Webhook signature is verified against the organization derived from `repository.owner.login` / `organization.login`, but the handlers act on the wholly separate, attacker-controlled `repository.full_name` field of the same payload - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by picking the GitHub App/secret for the organization named in `repository.owner.login` (or `organization.login`) and HMAC-verifying the raw JSON body against that secret. [1](#0-0) [2](#0-1)  Once the signature passes, the same raw JSON payload is handed unmodified to every registered handler. [3](#0-2)  The handlers, however, do not use `repository.owner.login` to scope their side effects — the base `Handler` class resolves the target `Stack`s from a **different** JSON field, `repository.full_name`. [4](#0-3) 

### Finding Description
The binding that should hold is:

`organization that signed/authenticated the webhook == organization that owns the repository the handler acts on`

But the code enforces:

`organization used to pick the verifying secret (repository.owner.login / organization.login)` while the effective binding is broken because the handler independently trusts `repository.full_name` to select which `Repository`/`Stack` records are mutated: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Both `repository.owner.login` (used to select the verifying secret) and `repository.full_name` (used to select the target `Repository`/`Stack`) come from the exact same attacker-supplied JSON body that is only integrity-protected as a whole blob via HMAC — nothing cross-validates that `repository.full_name`'s owner segment matches `repository.owner.login`. [2](#0-1) 

Concretely, `PushHandler` (a default handler for the `push` event) calls `stacks.not_archived.where(branch: ...).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`, where `stacks` is resolved purely from `repository.full_name`. [5](#0-4)  `Repository.from_github_repo_name` does a straightforward `owner/name` lookup with no relation to the field used for signature verification. [6](#0-5) 

Any GitHub organization/repository that has legitimately been onboarded into this Shipit instance has its own webhook secret configured for `Shipit.github(organization: X)`. [7](#0-6)  An admin of that organization can therefore craft an arbitrary JSON body, keep `repository.owner.login`/`organization.login` set to their own org "A" (so the signature check passes with secret A), but set `repository.full_name` to `"B/victim-repo"` — a completely different, unrelated stack tracked under organization "B" whose secret they do not know. The signature check in `verify_signature` only proves the body was signed by *some* onboarded organization, not that it was signed by the organization that owns the repository the handler subsequently mutates.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust boundary explicitly called out in scope. An attacker who administers a low-value/throwaway GitHub org "A" that has been added to this Shipit instance (and thus knows/controls org A's webhook delivery — a legitimate, non-privileged capability from Shipit's own trust model, since Shipit treats "an org is onboarded" as the trust anchor, not "this specific repo") can forge `push` webhooks that are accepted as valid and are then applied to any other stack "B/victim-repo" hosted in the same Shipit instance, by simply setting the `repository.full_name` field. This can trigger `Stack#sync_github` against the victim stack with an attacker-chosen `expected_head_sha`, causing the app's own GitHub credentials to be used to sync/record commits for the victim repository based on attacker-controlled input — an unauthorized cross-repository write into stack B's commit history/state, which can subsequently affect deploy eligibility and CI status association for repo B.

### Likelihood Explanation
Likelihood is moderate-to-high in any multi-tenant Shipit deployment (the documented and intended use case — many orgs/repos onboarded to one Shipit instance). No repository write access, session, or `ApiClient` token is required; only the ability to control webhook signing for one legitimately onboarded (but otherwise unprivileged w.r.t. the victim repo) organization, which is exactly the kind of "authenticated organization vs. written repository" mismatch called out as in-scope.

### Recommendation
After signature verification succeeds for organization `X` (derived from `repository.owner.login`/`organization.login`), the controller or `Handler` base class should assert that the `repository.full_name`'s owner segment equals `X` before resolving `stacks`/`Repository` records, rejecting the webhook (e.g., with a 422) if they diverge.

### Proof of Concept
1. Shipit instance has two onboarded organizations: `attacker-org` (with webhook secret known to the attacker admin) and `victim-org/victim-repo` (a tracked stack, secret unknown to attacker).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(webhook_secret_for_attacker-org, body)>` and POSTs to `/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the HMAC check passes. [1](#0-0) 
5. `PushHandler.call(params)` resolves `stacks` via `repository.full_name = "victim-org/victim-repo"`, unrelated to the organization that signed the request, and invokes `stack.sync_github(expected_head_sha: ...)` on the victim's stack. [4](#0-3) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

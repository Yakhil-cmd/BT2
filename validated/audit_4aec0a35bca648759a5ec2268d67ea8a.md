## Analysis

The `status` webhook handler confirms the impact path: `StatusHandler#process` looks up commits purely by `sha` — with no repository/organization scoping at all — and calls `commit.create_status_from_github!(params)` [1](#0-0) . Commit statuses drive CI-gating for deploys (`ci.require`/`ci.blocking` in `shipit.yml`), so forging a `status` event lets an attacker mark a matching-sha commit on a *different* stack as passing CI. `CheckSuiteHandler` and `PushHandler` similarly resolve targets from attacker-controlled payload fields (`stacks` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) with no cross-check against the identity used to verify the request signature [2](#0-1) .

### Title
Cross-Organization Webhook Forgery via Trust-Binding Mismatch Between Signature Verification Org and Acted-Upon Repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the same untrusted, attacker-suppliable JSON body [3](#0-2) [4](#0-3) . Once the HMAC check passes, every registered handler acts on a *different* field of that same body — `repository.full_name` — to decide which `Repository`/`Stack`/`Commit` to mutate [2](#0-1) [5](#0-4) . Nothing enforces that `repository.owner.login` (the field that selected the trust anchor) equals the owner encoded in `repository.full_name` (the field that determines what gets written). In a multi-organization Shipit deployment ("Using Multiple Github Applications", `docs/setup.md`), where each tenant organization has its own `webhook_secret` and independently controls a GitHub App pointed at the shared Shipit host, this is a direct analog of the XVS bug: the entity whose credential authenticated the message (`repository_owner` → org A's `webhook_secret`) is not the entity the payload actually writes to (`repository.full_name` → org B's stack/commit/repository).

### Finding Description
`Shipit.github(organization: repository_owner)` resolves the `GitHubApp` (and thus the `webhook_secret`) used for HMAC verification purely from `params.dig('repository', 'owner', 'login')` [3](#0-2) , and `lib/shipit.rb#github_app_config` looks this org up case-insensitively in the `secrets.github` multi-org map [6](#0-5) . This is the documented multi-tenant configuration where distinct organizations each provision their own GitHub App/`webhook_secret`, all delivering to the same `/webhooks` endpoint [7](#0-6) .

Every `Handler` subclass, however, derives the actual target of a mutation from `payload.dig('repository', 'full_name')` [2](#0-1) , which is resolved via `Repository.from_github_repo_name` — a straight `owner/name` split with no additional ownership check [5](#0-4) . `StatusHandler` is even weaker: it scopes only by commit `sha`, globally, with zero repository/organization filter at all [1](#0-0) .

Because `verify_webhook_signature` only HMACs the raw body against whichever secret was selected by `repository.owner.login`, an attacker who legitimately possesses their own organization's `webhook_secret` (e.g., tenant org "attacker-org", a real customer of the shared Shipit instance) can craft a payload where `repository.owner.login = "attacker-org"` (so their own secret validates) but `repository.full_name = "victim-org/private-repo"` (so the handler acts on the victim's data). The signature check and the data-mutation check are bound to two different fields of the same attacker-controlled body, breaking the equality: `org authenticated == org written`.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. Concretely:
- A forged `status` event can inject a fabricated passing/failing CI status onto any commit sha tracked by any stack on the shared instance, bypassing the `ci.require`/`ci.blocking` gates that guard deploy eligibility, potentially enabling an unauthorized deploy of an unreviewed commit belonging to a victim organization.
- A forged `push` event can trigger `GithubSyncJob` against a victim stack, and `pull_request` handlers can archive/unarchive/create review stacks belonging to a victim repository — all writes to a resource outside the authenticated organization's own scope.

This satisfies the Critical bar of "cross-repository writes" / "an unauthorized deploy" defined in the rules.

### Likelihood Explanation
Exploitability requires only that the attacker control one legitimate tenant's `webhook_secret` in a multi-org Shipit deployment — which is the documented, supported configuration for onboarding multiple customer organizations onto one shared instance, not a privileged or out-of-scope precondition. No `ApiClient` token, GitHub App private key, or repository write access on GitHub itself is needed; the attacker only needs to be able to send an HTTP POST with a body they sign themselves.

### Recommendation
In `WebhooksController#verify_signature` and/or in `Handler#repository_name`, enforce that the organization used to select the verifying `webhook_secret` (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` before any handler runs; reject the request (422) on mismatch. More robustly, bind webhook secret selection to a value not solely derived from the JSON body (e.g., a static per-organization webhook path/token) rather than trusting an unauthenticated organization field to select its own verification key.

### Proof of Concept
1. Configure Shipit with two tenant orgs, `OrgA` and `OrgB`, each with distinct `webhook_secret` values (per `docs/setup.md`'s multi-org config).
2. As an operator of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret`), build a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature` as `sha1=` + HMAC-SHA1(`OrgA`'s `webhook_secret`, raw body).
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully [3](#0-2) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` [2](#0-1) [5](#0-4)  and enqueues `GithubSyncJob` against `OrgB`'s stack — a write triggered by `OrgA`'s credentials against `OrgB`'s resource.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

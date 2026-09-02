### Title
Cross-repository commit-status injection via unscoped `sha` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the webhook secret) to validate a signature against using the organization derived from the payload's `repository.owner.login`/`organization.login` field. [1](#0-0)  That binds "the organization whose secret authenticated this request" to a specific org. However, `StatusHandler#process` never re-checks that binding: it looks up commits globally by SHA across the entire installation, with no scoping to the repository/organization that produced the signed payload. [2](#0-1) 

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.yml` keyed per GitHub org, as documented in `docs/setup.md`), each organization has its own `webhook_secret`. [3](#0-2)  `WebhooksController#verify_signature` picks the right `GitHubApp` for verification using `repository_owner`, computed strictly from the attacker-supplied JSON payload. [4](#0-3)  Once the signature matches *that* organization's secret, the entire payload is handed unchanged to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [5](#0-4) 

The base `Handler` class does scope lookups by `repository.full_name` via `Repository.from_github_repo_name` for handlers like `PushHandler`. [6](#0-5) [7](#0-6)  But `StatusHandler` deviates from that pattern entirely: it queries `Commit.where(sha: params.sha)` with no repository/stack scoping whatsoever and calls `commit.create_status_from_github!(params)` on every matching commit found anywhere in the Shipit instance. [2](#0-1) 

This breaks exactly the binding the rules describe: "an organization that authenticated versus the repository that is written." The organization whose `webhook_secret` validated the request (org B, attacker-controlled) is not the organization whose commit gets written (org A, victim), because `StatusHandler` performs no cross-check between the two. Git SHAs are 40-hex-character values that are often publicly known (commit hashes are not secret — they appear in GitHub UI, PR links, CI logs, etc., which are typically public even for private repos' collaborators, and are trivially guessable/collectable by anyone who can see any surface referencing them).

### Impact Explanation
An attacker who administers their own GitHub organization/repo (org B) with the Shipit GitHub App installed — and thus legitimately possesses org B's `webhook_secret` and can trigger genuine, validly-signed `status` webhook deliveries — can forge a `status` event payload where the top-level `repository.owner.login` is `org B` (so `verify_signature` succeeds), but the `sha` field is set to a commit SHA belonging to a stack/repository in an entirely different, unrelated organization (org A) tracked by the same Shipit instance. Because `StatusHandler` does not check that the commit's stack/repository matches the payload's `repository` field, the attacker can inject an arbitrary `state`/`context`/`target_url`/`description` status onto org A's commit.

This directly undermines Shipit's CI-gating mechanisms: `Commit#deployable?` and `ci.require`/`ci.blocking` checks rely on commit statuses to gate deploys, continuous delivery, and PR merges via the merge queue (`MergeRequest#reject_unless_mergeable!`). [8](#0-7)  By forging a fake `success` status with the exact `context` that org A's `shipit.yml` `ci.require` expects, an attacker with no access to org A can make an otherwise CI-failing or CI-pending commit `deployable?`/mergeable, resulting in an unauthorized deploy or merge of that commit in org A — a cross-organization write and a bypass of CI-based deployment gating, achieved purely by controlling a separate, unrelated repository.

### Likelihood Explanation
This requires the deployment to be configured for multiple GitHub organizations (a documented, supported configuration) and requires the attacker to know a target commit SHA in org A, which is generally discoverable (commit SHAs are not secrets; they are visible in PR URLs, status pages, CI links, and often even leak through Shipit's own UI to any authenticated user of the shared instance). No privileged Shipit session, API token, or GitHub write access to org A's repository is needed — only ownership/administration of any other organization onboarded to the same Shipit install (or the ability to trigger genuine webhook deliveries for it).

### Recommendation
Scope `StatusHandler#process`'s commit lookup to the repository identified by the signed payload, mirroring how `PushHandler`/`Handler#stacks` resolve via `Repository.from_github_repo_name(repository_name)`, e.g. restrict `Commit.where(sha: params.sha)` to `stacks.flat_map(&:commits)` or an equivalent join through `Repository`/`Stack` derived from `payload.dig('repository', 'full_name')`, so a status update can never be applied to a commit outside the repository that authenticated the webhook.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (victim, private repo, `webhook_secret: SECRET_A`) and `org-b` (attacker-owned, `webhook_secret: SECRET_B`), both installed on the same Shipit instance per the multi-org setup in `docs/setup.md`.
2. Attacker learns a commit SHA `deadbeef...` belonging to a stack tracked for `org-a` (e.g., from a public PR link, CI badge, or the shared Shipit UI).
3. Attacker crafts a `status` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "org-b" }, "full_name": "org-b/attacker-repo" },
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example/fake",
  "description": "forged"
}
```
4. Attacker computes `X-Hub-Signature` using `SECRET_B` (which they legitimately possess for their own org) and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` to `org-b`, fetches `Shipit.github(organization: 'org-b')`, and verifies successfully against `SECRET_B`. [1](#0-0) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the commit belonging to `org-a`'s stack (since the query is unscoped), calling `create_status_from_github!` to inject the forged `success` status. [2](#0-1) 
7. If `org-a`'s `shipit.yml` requires `ci/required-check`, the forged status makes the commit `deployable?`/mergeable, enabling an unauthorized deploy/merge in `org-a` triggered entirely by an actor with no access to `org-a`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

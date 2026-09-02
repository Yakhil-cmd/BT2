### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub organization derived from the payload's `repository.owner.login` (or `organization.login`), but `StatusHandler` (invoked after verification) never re-checks that the commit it updates actually belongs to that same organization/repository. It looks up commits by SHA alone, globally across the entire Shipit installation. This breaks the trust binding `organization_authenticated == repository_written`.

### Finding Description
The webhook authentication path only proves that the payload was signed by *some* configured organization's `webhook_secret`: [1](#0-0) [2](#0-1) 

Other handlers correctly scope their side effects to the repository named in the same payload, e.g. `Handler#stacks`/`repository_name` resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, which is what `PushHandler` uses: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, ignores `repository` entirely and updates *every* `Commit` record in the database whose `sha` matches the payload's `sha`, regardless of which stack/repository/organization that commit belongs to: [5](#0-4) 

Because Shipit is explicitly designed to host multiple, independent GitHub organizations on one instance (each with its own `webhook_secret`/App config, as shown in the multi-org secrets template), an organization admin who legitimately owns one tenant's GitHub App installation can produce a validly-signed `status` webhook for *their own* org, while the SHA field inside that payload is attacker-chosen content pointing at a commit that happens to exist in a *different* tenant's repository/stack: [6](#0-5) 

Git commit SHAs are not secrets and are trivially reproducible across repositories that share history/tree/parent/author/timestamp data (forks, vendored upstream commits, cherry-picks, or crafted commits with matching metadata). An attacker who controls their own tenant's repo can therefore commit content engineered to produce a target SHA that collides with a commit already present in a victim tenant's `Commit` table, then trigger (or replay) a signed `status` event from their own org to plant an arbitrary status (`state`, `context`, `target_url`, `description`) on the victim's commit.

### Impact Explanation
Commit statuses in Shipit feed `deployable_status`/`merge_status` gating (see the `Hook::EVENTS` list which explicitly tracks `deployable_status`/`merge_status`, and `Commit#create_status_from_github!`, which `StatusHandler` calls). Forging a passing/`success` status on a victim stack's commit can satisfy required-status gates used to authorize a deploy or merge on that other tenant's stack — i.e., an unauthorized deploy, achieved purely by an attacker who only holds legitimate, unprivileged control over their own (different) organization's GitHub App/webhook configuration, never touching the victim's credentials, `ApiClient` tokens, or GitHub account. This satisfies the Critical impact bucket ("an unauthorized deploy, rollback, or merge").

### Likelihood Explanation
Exploitation only requires: (1) a Shipit deployment configured for multiple organizations (an explicitly supported and documented configuration), and (2) the attacker being an admin of one such organization's GitHub App installation — no access to the victim org, no `ApiClient` token, no session, no TLS interception. The remaining requirement — engineering a colliding SHA — is the main practical constraint, but is achievable via crafted commits (adjustable author/committer timestamps, parent references, empty/no-op trees) shared or replayed between repositories, especially in test/staging setups or forks of common upstream projects tracked by both tenants.

### Recommendation
In `StatusHandler#process` (and any other handler that resolves objects purely from payload content), scope the lookup to the repository/organization that was actually verified in `WebhooksController#verify_signature`. Concretely, restrict the `Commit` lookup to commits belonging to stacks whose `Repository` matches `payload.dig('repository', 'full_name')`, mirroring the scoping already used by `Handler#stacks`, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently join through `Repository.from_github_repo_name(repository_name)` before filtering by `sha`, so a commit outside the authenticated repository can never be updated.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `org-a` (victim) and `org-b` (attacker-controlled), each with their own GitHub App/`webhook_secret`, per [6](#0-5) .
2. Victim's stack (`org-a/repo`) has an existing tracked `Commit` with sha `S` (e.g. an upstream commit both repos share, or crafted to collide).
3. Attacker, as admin of `org-b`, creates/pushes a commit with the same sha `S` into their own repo `org-b/repo` and triggers (or replays via GitHub's redeliver) a `status` event for it with `state: success`.
4. `WebhooksController#verify_signature` succeeds because the payload is genuinely signed with `org-b`'s webhook secret (`repository.owner.login == "org-b"`), per [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: "S")`, matching the victim's commit in `org-a/repo` as well, and calls `create_status_from_github!` on it, per [5](#0-4) , writing a forged `success` status onto `org-a`'s commit without any `org-a` credential ever being used.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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

### Title
Cross-repository commit status forgery via unscoped SHA lookup in webhook handler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook handler resolves the target commit by SHA only, without verifying that the commit belongs to the repository named in the (correctly signed) payload. Because the webhook signature only authenticates *which organization* sent the request, but not *which repository's data may be mutated*, any organization onboarded to the Shipit instance can forge a `commit_status` webhook that writes a status onto a commit belonging to a completely different organization's repository, as long as the two commits share a SHA value.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/webhook secret using only the organization login taken from the payload (`repository.owner.login`) and validates the HMAC over the raw body: [1](#0-0) 

This proves the request was signed by *some organization's* configured webhook secret — it establishes "organization authenticated." It does **not** constrain which repository's records the resulting handler is allowed to mutate.

The `status` event is then routed to `StatusHandler#process`, which looks up the target commit purely by SHA, globally across the entire `Commit` table, with no filter on repository/stack ownership: [2](#0-1) 

Every commit matching `params.sha` — regardless of which stack/repository it belongs to — has `create_status_from_github!(params)` invoked on it. Compare with `PushHandler`, which correctly scopes to `stacks` (repository-bound) before acting: [3](#0-2) 

`StatusHandler` has no equivalent scoping. This breaks the binding: **organization that authenticated (via `verify_signature`/`repository_owner`) == repository whose commit is written (via `Commit.where(sha:)`)**. The equality does not hold — verification proves org A signed the payload, but the write applies to any commit sharing that SHA, including commits that belong to org B's/another tenant's stack.

### Impact Explanation
Commit statuses recorded via this path are consumed by Shipit's deploy-safety mechanism (`release_status?`/`commit_status` checks referenced in `shipit.yml`/`cached_deploy_spec`), which gate whether a commit is considered deployable. An attacker who controls one onboarded, low-privilege repository (with its own legitimate webhook secret) can spoof a `success` (or any) status onto a commit belonging to an unrelated organization's stack, provided the SHAs coincide. Since this can flip a commit's deploy-safety status in another tenant's stack, it can lead to an unauthorized/unsafe deploy being permitted for a repository/organization the attacker does not control — this qualifies as a cross-repository write and a potential unauthorized deploy, both explicitly in-scope Critical impacts.

### Likelihood Explanation
Exploitation requires the attacker to control an organization/repository that is already onboarded onto the same Shipit instance (i.e., has a valid webhook secret configured through its own GitHub App/organization installation) — this is an "unprivileged" bar relative to the target organization, since the attacker needs no access to the victim organization at all. The remaining requirement is a SHA collision between a commit in the attacker's own repository and a commit tracked in the victim's stack; since git SHAs are 40-hex-character strings, exact organic collisions are not something an attacker can force at will, but Shipit is multi-tenant by design and any shared history (e.g., forks, template repos, monorepo splits, vendored code, or simply repositories that happen to share early commits) makes exact SHA matches plausible, and nothing in the code prevents the handler from acting once a match occurs.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the repository identified in the verified payload (e.g., join through `Stack`/`Repository` using `params.repository` full name) instead of matching on SHA alone across the entire table, mirroring the repository-scoping already done in `PushHandler`.

### Proof of Concept
1. Organization "Attacker" onboards a repository into the Shipit instance and is issued/configures its own valid `webhook_secret`.
2. Organization "Victim" has an existing repository/stack tracked by Shipit, with a commit whose SHA is `abc123...` (SHAs are public via GitHub UI/API).
3. Attacker crafts (or naturally has, e.g. via a shared base commit/fork) a commit with the identical SHA `abc123...`, and sends a `status` webhook event: `{"sha": "abc123...", "state": "success", "repository": {"owner": {"login": "Attacker"}, ...}}`, signed with Attacker's own valid webhook secret.
4. `WebhooksController#verify_signature` succeeds because it only checks that Attacker's org signed the payload with Attacker's secret: [1](#0-0) 
5. `StatusHandler#process` finds Victim's commit with matching SHA (query is unscoped by repository) and writes the forged `success` status to it: [2](#0-1) 
6. Victim's commit now shows a forged status that can satisfy a `commit_status`/deploy-safety check configured in Victim's `shipit.yml`, potentially allowing an unauthorized deploy of Victim's stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

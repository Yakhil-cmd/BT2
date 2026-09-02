## Analysis



### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on unrelated, unverified payload fields (`repository.full_name`, bare `sha`) — cross-repository status forgery ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC using `repository_owner`, derived from `payload.dig('repository','owner','login')` (or `organization.login`) [1](#0-0) [2](#0-1) . Once the HMAC is valid for *that* organization's secret, the event is dispatched to handlers that operate on completely different, unauthenticated fields of the same JSON body: `Handler#stacks` resolves the target `Repository` via `payload.dig('repository', 'full_name')` [3](#0-2) , and `StatusHandler#process` doesn't scope by repository at all — it matches globally on `Commit.where(sha: params.sha)` [4](#0-3) . Nothing binds the org whose secret validated the signature to the repository/commit that is actually mutated.

### Finding Description
The equality this breaks: **organization that authenticated == repository that is written**, which does not hold.

- Before the attacker's payload: for a legitimately-delivered GitHub webhook, `repository.owner.login` (used for signature-org selection) and `repository.full_name` (used for the actual DB lookup) always refer to the same repository, because GitHub itself constructs the payload.
- After an attacker-crafted payload: an actor who controls (or has push access enabling GitHub-triggered webhooks within) any one organization configured in Shipit's multi-org `github:` secrets block [5](#0-4)  can produce a JSON body where `repository.owner.login` names *their* org (so `Shipit.github(organization: repository_owner)` picks a webhook secret they can compute/know) while `repository.full_name` (for `PushHandler`, `CheckSuiteHandler`, etc.) or `sha` (for `StatusHandler`) names an artifact belonging to an entirely different, unrelated repository/stack tracked by the same Shipit instance.
- `StatusHandler` is the most severe: it does not even reference `repository.full_name` — any correctly-HMAC-signed `status` event (signed with the attacker's own org's secret) can create a `Status` record on **any** `Commit` row in the database sharing the given `sha`, regardless of which repository or organization owns it [4](#0-3) .

Root cause is the disjoint field usage: `WebhooksController#repository_owner` (path: `repository.owner.login` / `organization.login`) vs. `Handler#repository_name` (path: `repository.full_name`) vs. `StatusHandler`'s unscoped `params.sha` [2](#0-1) [3](#0-2) .

### Impact Explanation
This is a cross-repository write: an entity that only controls one configured GitHub organization's webhook secret can forge commit statuses (and, via `PushHandler`, trigger `sync_github`/branch-sync activity [6](#0-5) ) against stacks/commits belonging to a different organization it has no legitimate access to. Since Shipit deploy/merge safety gating relies on `Commit`/`Status` records (`create_status_from_github!`), an attacker able to inject fabricated "success" statuses for commits in a repository they don't control could undermine required-check gating used to permit deploys or merges in that unrelated repository — matching the "unauthorized deploy" / "cross-repository writes" impact class.

### Likelihood Explanation
Requires only that Shipit is configured for more than one GitHub organization (documented, supported feature [5](#0-4) ) and that the attacker controls one such tenant's webhook secret/delivery path (e.g., is able to make GitHub deliver, or replay, a validly-HMAC'd webhook for their own org). No repository write access to the victim repository nor any Shipit session/API token is needed — only crafting the JSON body of a webhook whose HMAC matches a secret the attacker legitimately possesses for their own onboarded org.

### Recommendation
Bind the field used for signature-org selection to the same field used for repository resolution: after HMAC verification, re-derive `repository_name`/target repository strictly from `repository.owner.login` (the verified value), not from `repository.full_name` independently. In `StatusHandler` (and any other handler), scope the lookup by the verified repository (e.g., `stacks.commits.where(sha: params.sha)`) instead of a global, unscoped `Commit.where(sha:)`.

### Proof of Concept
1. Shipit is configured with two orgs in `secrets.yml`: `org-a` (attacker-controlled, webhook secret known to attacker) and `org-b` (victim, tracked stacks/commits).
2. Attacker computes `X-Hub-Signature` using `org-a`'s webhook secret over a payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sha": "<victim commit sha in org-b>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and validates successfully because the attacker signed with `org-a`'s real secret [1](#0-0) .
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit irrespective of `org-a` vs `org-b` — and creates a forged `success` status on it [4](#0-3) .

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

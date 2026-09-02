## Finding

### Title
Webhook Authenticates Repository Owner but Writes to a Different Repository (`repository.full_name`) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
The webhook signature is verified against the GitHub App configured for `repository.owner.login` (or `organization.login`), but the handler that actually writes state resolves the target `Stack`/`Repository` from an entirely different, independently-attacker-controlled field: `repository.full_name`. These two fields are never bound to each other by the HMAC check, so an org whose webhook secret is known can forge events that are attributed to any other repository tracked by the Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects which `github_app`/`webhook_secret` to verify the raw payload against using: [1](#0-0) 
and derives the signing org purely from the unverified JSON body: [2](#0-1) 

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same raw `params` to a handler that resolves the affected `Stack` from a *different* field of the same payload: [3](#0-2) 

`repository_name` (`repository.full_name`) and `repository_owner` (`repository.owner.login`) are two separate, attacker-supplied fields inside the same signed body. The HMAC only proves that *some* secret-holder produced the whole byte string; it does not enforce that `full_name` is consistent with `owner.login`. Any entity that legitimately controls a GitHub organization/repository with the Shipit App installed (and thus knows that org's `webhook_secret`) can craft an HTTP request directly to `/webhooks` with:
- `repository.owner.login` = their own org (so `verify_signature` looks up and validates against a secret they know), and
- `repository.full_name` = a victim org/repo tracked by the same Shipit instance.

This breaks the binding: **organization authenticated (`repository.owner.login`) ≠ repository written (`repository.full_name`)**.

`StatusHandler` compounds this further — it doesn't even scope by repository, matching purely on `sha` across the whole database: [4](#0-3) 
and `PushHandler` triggers `sync_github` for a victim's stacks using an attacker-chosen branch/`expected_head_sha`: [5](#0-4) 

### Impact Explanation
An attacker who is not a Shipit user and holds no `ApiClient` token — only a legitimate GitHub App installation for their own, unrelated organization — can forge webhook deliveries that are accepted as authentic for any repository/stack hosted on the same Shipit instance. This allows forging commit statuses (`status` event) to mark arbitrary commits on a victim's tracked repository as CI-green, which can unblock/trigger continuous delivery and result in an unauthorized deploy of attacker-influenced state, satisfying the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
Exploitation requires only that the attacker control the webhook secret of *any* single organization/repo already integrated with the target Shipit instance (a normal, unprivileged action available to any org admin who onboards their own repo), plus knowledge of a victim repository's `full_name` that is also tracked by the same instance — both easily satisfied in any multi-tenant/shared Shipit deployment.

### Recommendation
After signature verification, re-derive the repository/organization strictly from the same field used to select the verifying secret (or vice-versa), and reject the webhook if `repository.full_name`'s owner segment does not match `repository_owner`/`organization.login` used in `verify_signature`. Additionally, scope `StatusHandler` lookups by repository, not just `sha`.

### Proof of Concept
1. Attacker owns GitHub org `attacker-org`, which has the Shipit GitHub App installed with a known `webhook_secret` (a legitimate, unprivileged setup step for their own repo).
2. Attacker crafts a `status` (or `push`) JSON payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over this exact body and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches that org's `github_app`, and the HMAC checks out — request is accepted.
5. `StatusHandler#process` matches `Commit.where(sha: params.sha)` (no repo scoping at all) and creates a forged success status on the victim's commit, independent of `victim-org`'s real webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

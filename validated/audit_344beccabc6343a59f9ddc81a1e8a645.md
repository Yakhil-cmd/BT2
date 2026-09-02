### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but the write path resolves the target repository from the independent, unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the inbound HMAC signature against, using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1)  However, once the signature check passes, every webhook `Handler` (e.g. `PushHandler`) resolves the actual `Stack`/`Repository` to mutate using a *different* payload field, `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`. [3](#0-2)  These two fields are never cross-checked against each other.

### Finding Description
This is the same class of bug as the `withdrawRedundant` finding: the field that is checked (bound to the trust decision) is not the field that is acted upon. In `withdrawRedundant`, the condition inspects `balance` while the executed transfer branch operates on the full token balance; here, `verify_signature` inspects `repository.owner.login`/`organization.login` to pick the trusted organization's secret, while `PushHandler#process` (via `Handler#stacks`) picks the actually-affected `Stack` using `repository.full_name`. [4](#0-3) 

Additionally, `GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the selected organization: `return true unless webhook_secret`. [5](#0-4)  In a multi-organization Shipit deployment (`Shipit.github(organization: ...)` resolves per-org config), any organization entry that is configured without a `webhook_secret` value becomes an authentication bypass for signature verification whenever an attacker sets `repository.owner.login` to that organization's name.

Binding broken, stated as an equality that should hold but doesn't:
`organization authenticated by verify_signature (repository.owner.login / organization.login)` == `repository actually written to by the handler (repository.full_name)`

Before the attacker's request: for any real GitHub-originated webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always the same value, because both are derived from the same GitHub repository object — the fields never diverge in legitimate traffic.

After the attacker's request: because `WebhooksController#create` parses arbitrary `request.raw_post` JSON supplied over HTTP [6](#0-5) , an attacker who can produce a signature that validates for *some* configured organization (trivially true if that organization has no `webhook_secret` set) can freely set `repository.full_name` to `victim-org/victim-repo` while keeping `repository.owner.login` pointed at the no-secret organization. The signature check passes against the wrong (attacker-controlled) organization, and the write (`stack.sync_github(expected_head_sha: params.after)`) is dispatched against the victim stack resolved purely from `full_name`.

### Impact Explanation
This lets an unprivileged, unauthenticated network attacker forge push/status/check_suite events for a repository/stack they do not control, as long as any other organization in the Shipit multi-tenant config lacks a `webhook_secret` (or the attacker can otherwise obtain one org's secret without having any relationship to the victim org). `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` against the victim's stack, which drives Shipit's notion of the "current"/deployable head commit and can influence continuous-deployment and merge/status flows for a repository the attacker was never granted access to — a cross-repository/cross-organization write triggered without valid authorization for the target repo, matching the report's "backdoor" pattern of a check on one value gating an action on a different, unguarded value.

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one configured GitHub organization/App whose `webhook_secret` is blank or otherwise known/guessable to the attacker — a realistic condition in staging/dev-only org entries, legacy configs, or orgs added before secrets were rotated in a multi-org `secrets.yml`. Given such a config, no repository access, session, or API token is needed; the attack is a single unauthenticated HTTP POST with a crafted JSON body and mismatched `repository.owner.login` vs `repository.full_name`.

### Recommendation
Bind the identity used to select/verify the webhook secret to the exact same field used to resolve the affected `Repository`/`Stack`. Concretely:
- Have `WebhooksController#verify_signature` and `Handler#repository_name` derive the organization/repo from the *same* payload path (e.g., always split `repository.full_name`), and reject the request if `repository.owner.login` (when present) disagrees with the owner segment of `repository.full_name`.
- Remove or gate the `return true unless webhook_secret` fallback in `GithubApp#verify_webhook_signature` so that a missing secret fails closed instead of open, or at minimum log/alert and refuse to process state-changing handlers (push, status, check_suite) when no secret is configured.

### Proof of Concept
1. Deployment has organizations `orgA` (secret configured) and `orgB` (no `webhook_secret` set) both registered in Shipit's GitHub app config, and `orgA` owns a real target repository `orgA/prod-app` with an active `Stack`.
2. Attacker (no credentials, no repo access) sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already present in orgA/prod-app's history>",
  "repository": {
    "owner": { "login": "orgB" },
    "full_name": "orgA/prod-app"
  }
}
```
3. `repository_owner` resolves to `orgB`; `Shipit.github(organization: 'orgB').verify_webhook_signature` returns `true` unconditionally because `orgB` has no `webhook_secret`. [7](#0-6) 
4. `PushHandler#process` resolves `stacks` via `repository.full_name` = `orgA/prod-app` [3](#0-2) , and calls `stack.sync_github(expected_head_sha: params.after)` on the real `orgA/prod-app` stack [4](#0-3)  — an org-authorization boundary crossing achieved purely by mismatching two payload fields whose consistency was never enforced.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

### Title
Webhook organization authentication is not bound to the repository/commit the handler writes to, enabling cross-tenant status/sync forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The external report flags that `RewardDistributor.sol` checks nothing that ties the recipient the code *intends* to pay to the value actually sent. The same class of bug — verifying one identity but acting on a different, uncontrolled one — exists in Shipit's webhook pipeline: the HMAC signature is verified against the GitHub *organization* derived from the payload, but the handlers that execute afterwards act on a `repository`/`commit` field taken from the very same attacker-controlled payload, with no requirement that it belong to the authenticated organization.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/organization secret to check against using a payload field: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the JSON body (`repository.owner.login`, falling back to `organization.login`). The HMAC in `GithubApp#verify_webhook_signature` only proves "whoever holds *that* organization's `webhook_secret` produced these exact bytes" — it says nothing about whether the rest of the payload (e.g. `repository.full_name`, or a raw commit `sha`) actually belongs to that organization: [3](#0-2) 

Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled JSON to handlers that resolve the target purely from other payload fields, independent of the field used for authentication:

- `Handler#stacks`/`#repository_name` resolve the target repository from `payload.dig('repository', 'full_name')`, a string with no required relationship to `repository.owner.login`/`organization.login` used for signing: [4](#0-3) 

- `StatusHandler#process` is worse: it does not scope by repository at all, it looks up **any** commit in the entire installation by raw `sha` and writes a CI status to it: [5](#0-4) 

- `PushHandler#process` similarly triggers a GitHub sync for any stack whose repository's `full_name` matches the attacker-supplied string, using an attacker-chosen `expected_head_sha`: [6](#0-5) 

**Binding broken:** `organization authenticated by signature == organization whose repository/commit is written` is assumed but never enforced. Before the attack: an org's webhook secret authorizes writes only to that org's own repositories/commits (implicit trust model). After: an org that legitimately owns a webhook configured on the shared Shipit instance (and thus knows its own `webhook_secret`) can sign a payload with its own secret while filling `repository.full_name` / commit `sha` with values belonging to a completely unrelated tenant's repository, and the handler will act on that unrelated target because it never re-checks the field the signature was scoped to.

### Impact Explanation
Because `StatusHandler` performs a global, unscoped `Commit.where(sha: ...)` lookup, an attacker who controls any organization/repository configured on a shared, multi-tenant Shipit instance can forge arbitrary CI "status" events for commits in **other repositories**, which is a cross-repository write. Since commit statuses gate `deployable_status`/`merge_status` and thus a stack's "is deployable" state, this can be used to falsify CI results and enable an unauthorized deploy of a stack the attacker does not own or have any legitimate access to. `PushHandler` extends the same class of forgery to trigger `stack.sync_github` on an unrelated repository. This satisfies the "cross-repository writes" / "unauthorized deploy" bar.

### Likelihood Explanation
Exploitation only requires that the attacker administers one legitimately configured organization/repository on the shared Shipit deployment (so they know their own `webhook_secret`, which they were given when the integration was set up) — no access to the target's secret, no Shipit session, and no `ApiClient` token is needed. They simply send a normal webhook POST to `/webhooks` with `X-Hub-Signature` computed with their own secret, but with `repository.full_name` / commit `sha` values pointing at a different tenant. This is a realistic, low-privilege attacker path in any Shipit install serving more than one organization/repository.

### Recommendation
After `verify_webhook_signature` succeeds, re-derive the acting `Repository`/`Stack`/`Commit` scope strictly from the same authenticated `repository_owner`/organization used for verification (or explicitly re-validate that `payload.dig('repository','owner','login')` matches the `full_name` owner and that any commit looked up in `StatusHandler`/`CheckSuiteHandler` belongs to a stack under that verified owner) before executing any handler logic, rather than trusting unrelated fields inside the same signed-but-unchecked JSON body.

### Proof of Concept
1. Attacker legitimately owns GitHub org `attacker-org`, which has a `Shipit::GithubHook`/GithubApp config with a known `webhook_secret` on the shared Shipit instance.
2. Attacker crafts a `status` event payload:
   ```json
   {
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"},
     "sha": "<sha-of-a-commit-belonging-to-victim-org/victim-repo>",
     "state": "success",
     "context": "ci/attacker-forged"
   }
   ```
3. Attacker signs the raw body with `attacker-org`'s own `webhook_secret` and sends it as `X-Hub-Signature` to `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s GithubApp, and the signature check passes because the attacker used the correct (their own) secret [1](#0-0) .
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` — which matches the victim's commit regardless of owner — and calls `create_status_from_github!`, writing a forged CI status onto a repository the attacker never controls [5](#0-4) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

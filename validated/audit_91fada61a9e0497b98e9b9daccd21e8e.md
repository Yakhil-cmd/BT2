### Title
Webhook signature verified against `repository.owner.login`'s org while `PushHandler` mutates the stack resolved from `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/org config used for HMAC verification from `repository.owner.login`, but `Shipit::Webhooks::Handlers::Handler#stacks` resolves the mutated stack from `repository.full_name`, a completely independent field of the same JSON body. An attacker can put a no-secret (or attacker-controlled) org in `owner.login` while pointing `full_name` at a victim org/repo, causing the signature check to pass trivially and `PushHandler` to sync/mutate the victim's production stack.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`org(repository.owner.login used to select webhook_secret in verify_signature) == org(repository.full_name used by Handler#stacks to resolve the mutated Repository/Stack)`

Code path:
- `Shipit::WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) 
- `#verify_signature` calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(...)`, only using that org's `webhook_secret` [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no configured `webhook_secret` (`return true unless webhook_secret`) [3](#0-2) 
- Independently, `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, and `Handler#stacks` uses that to look up `Repository.from_github_repo_name(repository_name)` and its `stacks`, entirely disconnected from `repository_owner` [4](#0-3) 
- `PushHandler#process` then iterates every non-archived stack on the parsed branch and calls `stack.sync_github(expected_head_sha: params.after)` [5](#0-4) 

Exploit flow: attacker crafts a `push` webhook body where `repository.owner.login` = `"attacker-org"` (an org Shipit has no `webhook_secret` configured for, or one the attacker controls) and `repository.full_name` = `"victim-org/victim-repo"` (a repository backing a real, production-environment Shipit stack). Because `verify_signature` resolves the app/secret using only `owner.login`, and the no-secret branch short-circuits to `true`, the forged signature (or even an absent one) is accepted. `PushHandler` then resolves stacks purely from `full_name`, finds the victim's production stack, and calls `sync_github(expected_head_sha: params.after)`, which can append attacker-chosen commits and drive the stack's continuous delivery pipeline forward — no relationship between the verified org and the mutated org is ever checked.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is handled, `ExplicitParameters` schema only validates presence of `ref`/`after`, and there is no `Repository`-format or cross-field validation anywhere in this path tying `repository.owner.login` to `repository.full_name`'s owner segment.

### Impact Explanation
The attacker causes GitHub-authenticated-appearing writes (`stack.sync_github`) against a victim's production-environment stack without ever possessing that victim org's `webhook_secret`. This is a payload for one repository (attacker's own no-secret org) mutating another repository's/org's stack — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" and "unauthorized deploy/rollback/merge of attacker-controlled code," since `sync_github` drives the deploy pipeline via `expected_head_sha`. The attack is repeatable against any victim repository whose owning org's login string the attacker can predict/guess is not itself an authentication requirement — only the `full_name` needs to match a real Shipit-tracked stack, while `owner.login` just needs to be any org with no `webhook_secret` configured in `Shipit.github_teams`/app config (or one fully controlled by the attacker).

### Likelihood Explanation
Preconditions: (1) Shipit must be configured with at least one org that has no `webhook_secret` set (a plausible/common misconfiguration, e.g., a low-security or personal org integrated for testing), and (2) the victim repository/stack must exist with production environment configured. The attacker needs no Shipit session, API token, or GitHub secret — only the ability to send an unauthenticated `POST /webhooks` HTTP request with a crafted JSON body and an `X-Github-Event: push` header. This is trivially repeatable and low-cost.

### Recommendation
Verify the webhook signature using the same org/repository identity that will be used to resolve the mutated stack. Specifically, derive `repository_owner` from `repository.full_name`'s owner segment (or validate that `repository.owner.login` matches the owner segment of `repository.full_name`) before calling `Shipit.github(organization: ...)`, and reject the webhook if they diverge. Also consider requiring `webhook_secret` to be present for all configured orgs (removing the "return true unless webhook_secret" bypass) so an unconfigured/attacker org can never satisfy signature verification.

### Proof of Concept
minitest plan (under `test/controllers/webhooks_controller_test.rb`, no live GitHub):
1. Configure two orgs in `Shipit.github_teams`/app config: `"attacker-org"` with no `webhook_secret`, and `"victim-org"` with a `webhook_secret` set.
2. Create a `Shipit::Stack` backed by `Repository` with `full_name: "victim-org/victim-repo"`, `environment: "production"`, `branch: "master"`.
3. POST to `/webhooks` with header `X-Github-Event: push`, no/garbage `X-Hub-Signature`, and JSON body:
   `{"ref": "refs/heads/master", "after": "<attacker_sha>", "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}}`
4. Assert the equality before: `repository_owner == "attacker-org"` while `repository.full_name`'s owner segment `== "victim-org"` (mismatch).
5. Assert response is `200 OK` (not `422`), proving signature verification passed despite the mismatch.
6. Assert `stack.sync_github` was invoked (e.g., stub/mock `Stack#sync_github` and assert it received `expected_head_sha: "<attacker_sha>"`) — proving the victim's production stack was mutated by a request authenticated under a different org's identity.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

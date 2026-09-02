### Title
Push webhook signature verification is scoped to `repository.owner.login`, but stack lookup is scoped to a separate, independently-forgeable `repository.full_name` field, letting an unprivileged attacker sync/deploy an arbitrary victim stack - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret`) using `params.dig('repository','owner','login')`, while `Shipit::Webhooks::Handlers::Handler#stacks` selects the target `Repository`/stacks using the independent JSON field `payload.dig('repository','full_name')`. Because the entire JSON body is attacker-controlled and unsigned whenever any configured GitHub organization has a blank `webhook_secret`, an attacker can set `repository.owner.login` to that no-secret org (to pass `verify_webhook_signature`) while setting `repository.full_name` to an arbitrary victim `owner/repo` to route the `push` event to the victim's stacks.

### Finding Description
The broken binding is the implicit assumption that:
`verify_signature`'s authenticated owner (`params.dig('repository','owner','login')`) == the owner encoded in `repository_name` (`payload.dig('repository','full_name')`) used by `Handler#stacks`.

Trace:
- `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) calls `Shipit.github(organization: repository_owner)` where `repository_owner` (line 59-62) reads `params.dig('repository', 'owner', 'login')`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) returns `true` unconditionally `unless webhook_secret` — i.e., any org configured without a `webhook_secret` accepts arbitrary unsigned bodies.
- On success, `WebhooksController#create` parses the same raw JSON and dispatches to `PushHandler.call(params)`.
- `Handler#initialize`/`#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38) computes `repository_name` from `payload.dig('repository', 'full_name')` — a **different JSON key path** than the one used for signature/org selection — and loads `Repository.from_github_repo_name(repository_name)&.stacks`.
- `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) then runs `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`, which can append commits and drive continuous delivery for any matched stack.

Since `repository.owner.login` and `repository.full_name` are two independent fields inside the same attacker-controlled JSON body, nothing forces `full_name`'s owner segment to equal `owner.login`. An attacker who knows (a) any Shipit-configured GitHub org lacking a `webhook_secret`, and (b) the `owner/repo` and branch name of a victim stack, can craft:
```json
{
  "ref": "refs/heads/<victim-branch>",
  "after": "<any sha>",
  "repository": {
    "owner": { "login": "<no-secret-org>" },
    "full_name": "<victim-owner>/<victim-repo>"
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` with no HMAC check at all — the body is fully forged. `PushHandler` then resolves stacks via `full_name = "<victim-owner>/<victim-repo>"`, entirely bypassing the intended tenant isolation. No existing guard (`drop_unhandled_event`, `ExplicitParameters` schema, model validations on `Repository`/`Stack`) checks that the field used for authentication matches the field used for authorization/lookup.

### Impact Explanation
An unprivileged internet attacker can force `Shipit::Stack#sync_github` to run against any victim stack configured in the target Shipit instance, without owning, having push access to, or controlling any webhook secret for that repository. This is a payload for one repository (the no-secret org) mutating another repository's stack/commit state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Depending on stack configuration (continuous deployment enabled), this can additionally trigger unauthorized deploys. The attack is repeatable against any stack whose `owner/repo` and branch name are known/guessable, as long as at least one org in the Shipit deployment has no `webhook_secret` configured.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization configured in `Shipit.github_configs` with a blank/missing `webhook_secret` (the "no-secret organization" case explicitly named in the question), and (2) knowledge of a victim stack's `owner/repo` full name and branch. Both are low-cost/observable (organization names and repos are often public, and Shipit stack URLs are visible in the UI). No authentication, GitHub token, or webhook secret is required — the attacker only needs to `POST /webhooks` with the crafted JSON and a `X-Github-Event: push` header. This is trivially repeatable.

### Recommendation
Bind authentication and authorization to the same field. Specifically, derive `repository_owner` (used for `verify_signature`) and `repository_name` (used for stack lookup in `Handler#stacks`) from the same normalized value (e.g., always split `repository.full_name` for both, or explicitly assert `repository.owner.login == repository.full_name.split('/').first` before dispatch), and reject the request if they diverge. Additionally, consider treating a blank `webhook_secret` for an org as "reject all webhooks for repos not explicitly allow-listed" rather than "accept unconditionally," since `verify_webhook_signature` returning `true` on blank secret effectively disables authentication for that org's-and, via this bug, other orgs'-payloads.

### Proof of Concept
minitest plan (under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/push_handler_test.rb`, no live GitHub):
1. Configure `Shipit.github_config` (via test helper) with two orgs: `"no-secret-org"` (no `webhook_secret` key) and `"victim-org"` (with a real `webhook_secret`).
2. Create `Repository.create!(owner: "victim-org", name: "victim-repo")` and an associated `Stack` with `branch: "main"` and a known head commit.
3. Assert the binding before exploitation: `webhooks_controller.send(:repository_owner)` (via a spy/stub of the request) should equal the owner segment of `repository.full_name` for any legitimate webhook — establish this equality as the invariant.
4. POST to `/webhooks` with header `X-Github-Event: push`, no/garbage `X-Hub-Signature`, and body:
```json
{"ref":"refs/heads/main","after":"deadbeef...","repository":{"owner":{"login":"no-secret-org"},"full_name":"victim-org/victim-repo"}}
```
5. Assert response is `200 OK` (not `422`), proving signature verification passed via the no-secret org.
6. Assert `Shipit::Stack#sync_github` was called (e.g., stub/mock `sync_github` on the victim stack instance, or assert a `GithubSyncJob` was enqueued for the victim stack) with `expected_head_sha: "deadbeef..."`, proving the victim stack (authenticated by `victim-org`'s secret in normal operation) was mutated by a payload that never carried `victim-org`'s `webhook_secret`.
7. Re-evaluate the equality from step 3 after the request: `owner.login ("no-secret-org") != full_name.split('/').first ("victim-org")` — the binding is broken, confirming the vulnerability. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

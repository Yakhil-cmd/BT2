### Title
Webhook signature verification is keyed on `repository.owner.login` but stack resolution uses `repository.full_name` — no cross-check binds the two - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to validate the HMAC using `repository_owner` (`payload.dig('repository','owner','login')`), while `Handler#stacks` resolves the affected `Repository`/`Stack` using `payload.dig('repository','full_name')`. These two payload fields are never checked against each other, so a webhook whose signature is valid for org A can carry a `full_name` pointing at org B's repository and still be processed.

### Finding Description
The broken binding: `verified_organization = payload['repository']['owner']['login']` must equal `owner_segment_of(payload['repository']['full_name'])`, but nothing in the code enforces this equality.

Path:
- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that org's `webhook_secret` via `GitHubApp#verify_webhook_signature`. [1](#0-0) [2](#0-1) 
- Once verified, `create` dispatches the *entire raw JSON body* — including the `repository.full_name` field — to the registered handlers, unmodified. [3](#0-2) 
- `Handler#stacks` and `#repository_name` resolve the target repository purely from `full_name`, with no reference back to `owner.login` or to the organization that was actually authenticated. [4](#0-3) 
- `Repository.from_github_repo_name` splits `full_name` on `/` and looks the record up directly, with no ownership check against the verifying org. [5](#0-4) 

Root cause: signature verification authenticates "this HTTP body was signed by whoever holds `attacker-org`'s `webhook_secret`," but the code implicitly (and incorrectly) treats that as authenticating "this body's `repository.full_name` is trustworthy," even though `full_name` and `owner.login` are independent, attacker-suppliable JSON fields in a POST body sent directly to `/webhooks` (this is a raw HTTP endpoint, not something GitHub exclusively can reach — anyone can `POST` a hand-crafted body as long as the HMAC matches a secret they know).

Exploit: an attacker who administers "attacker-org" (a legitimately onboarded tenant with its own `webhook_secret` entry in Shipit's `github_apps` config, which the attacker — as the org's webhook configurator — knows) crafts a raw JSON push payload with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, computes `HMAC-SHA1(attacker-org-secret, body)`, and POSTs it to `/webhooks` with that signature in `X-Hub-Signature`. `verify_signature` picks attacker-org's `GitHubApp`, the HMAC matches, and the request proceeds. `PushHandler#process` (via `Handler#stacks`) then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and operates on victim-org's `Stack`s (e.g., enqueuing `GithubSyncJob`), even though the request was never authenticated by victim-org's secret.

None of the existing guards catch this: `drop_unhandled_event` only checks the event type; `verify_signature` never compares `repository_owner` to `full_name`'s owner segment; `Repository.from_github_repo_name`/`Repository` validations only constrain character format, not ownership provenance; there is no `ExplicitParameters` check tying `owner.login` to `full_name`.

### Impact Explanation
A request authenticated only by attacker-org's webhook secret can trigger repository/stack-level side effects (e.g., `GithubSyncJob`, and depending on which push/PR handler is invoked, commit or task-affecting behavior) scoped to a completely different organization's repository. This is a cross-tenant write where one repository's (attacker's) credentials mutate another (victim's) stack state — matching the Critical category "a payload for one repository mutating another's stack, commit, task, or team." It's repeatable against any repository the attacker can guess/know the `owner/name` of, for as long as attacker-org remains a configured tenant.

### Likelihood Explanation
Requires: (1) Shipit is deployed multi-tenant, with more than one organization configured in `github_apps`/`webhook_secret`; (2) the attacker controls (or is the webhook administrator for) one such tenant org, so they know that org's `webhook_secret`. Given that, the attack costs a single crafted HTTP POST with a correctly computed HMAC — no GitHub API access, no session, no other org's secret needed. This is realistic for any Shipit instance serving multiple organizations/customers, which is an explicitly supported configuration (`Shipit.github(organization:)` keys off multiple orgs).

### Recommendation
After signature verification, validate that the authenticated `repository_owner` (or `organization.login`) matches the owner segment of `payload['repository']['full_name']` before dispatching to handlers; reject the request (422) on mismatch. Alternatively, have `Handler#stacks` resolve repositories scoped by the verified organization rather than trusting `full_name` outright.

### Proof of Concept
Minitest integration test under `test/controllers/webhooks_controller_test.rb` (out-of-scope path but describing the plan conceptually):
1. Configure two orgs in test `github_apps`: `"attacker-org"` with `webhook_secret: "attacker-secret"`, and `"victim-org"` with a different/absent secret.
2. Create `Repository` for `victim-org/victim-repo` with an associated `Stack`.
3. Build a push payload JSON with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', "attacker-secret", body)`.
5. POST to `/webhooks` with that header and `X-Github-Event: push`.
6. Assert response is `200`/`ok` (not `422`), and assert `GithubSyncJob` was enqueued with the victim stack's id — proving `owner.login == "attacker-org"` (verified) while `full_name`'s owner (`"victim-org"`) was used to select the mutated stack, violating the required equality.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

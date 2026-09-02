### Title
Webhook signature verification authenticates the *payload's `owner.login`* organization, but every event handler acts on the *payload's `repository.full_name`* — allowing a request signed with one organization's secret to mutate another organization's Stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` derives the organization used to look up the HMAC secret from attacker-controlled JSON, not from any GitHub-verified value: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), and `Shipit.github(organization: repository_owner)` is used only to fetch the `webhook_secret` to verify `X-Hub-Signature` against the raw body [3](#0-2) .

Every event handler, however, resolves the target `Repository`/`Stack` records using a *different* field of the same attacker-controlled JSON — `repository.full_name` — via the shared base class: [4](#0-3) 

`Repository.from_github_repo_name` splits `full_name` into `owner/name` and does a direct DB lookup with no relation enforced back to the `owner.login` value that authenticated the request: [5](#0-4) 

Nothing ties `repository.owner.login` (used to select the HMAC secret) to `repository.full_name` (used to select which `Repository`/`Stack` is mutated). A legitimate GitHub webhook always keeps these consistent, but the controller trusts the raw JSON body itself for both values, and the signature only proves knowledge of *a* configured `webhook_secret` — not that the secret's owning organization matches the repository the handler is about to act on.

Concretely, `PushHandler#process` (inherited `stacks`) is reachable this way: [6](#0-5) 

and this same `Handler#stacks`/`repository_name` pattern is shared by every other registered handler (`StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*` handlers, `MembershipHandler`) [7](#0-6) , so the mismatch is not limited to one event type.

**Broken binding (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository.owner.login / organization.login)` == `repository whose Stack/Commit state the handler mutates (repository.full_name)`

Before the attack: for genuine GitHub webhooks these two values always describe the same repository, so the equality holds implicitly.
After the attacker's request: an attacker who has installed the Shipit GitHub App on their **own** GitHub organization (a completely unprivileged action — no Shipit session, no `ApiClient` token, no access to the victim's org needed) knows that organization's `webhook_secret`. They can POST a crafted JSON body directly to `/webhooks` with `repository.owner.login` (or `organization.login`) set to their own org (so `verify_signature` computes a valid HMAC using their known secret) while `repository.full_name` is set to `victim-org/victim-repo`. `verify_signature` passes, but the handler operates on the victim's `Stack` via `Repository.from_github_repo_name('victim-org/victim-repo')`.

### Impact Explanation
This lets an attacker who controls only their own GitHub organization's webhook secret inject and authenticate cross-organization events against a victim `Stack` they have no relationship to — a credential/authentication boundary is bypassed entirely, since the org that "proved" the signature is not the org whose data gets written. Depending on which handler processes the event this can trigger unwanted GitHub syncs, forged commit-status records, or check-suite driven job scheduling against a victim's stack, all without ever touching the victim's GitHub App credentials, `ApiClient` tokens, or session — satisfying the "authentication bypass" / cross-repository write class of impact.

### Likelihood Explanation
Likelihood is high for any attacker capable of installing a GitHub App on an org they control and configuring it with Shipit (a normal, unprivileged onboarding action for a multi-tenant Shipit deployment), since crafting the JSON body with mismatched `owner.login` vs `full_name` requires no special access — only knowledge of their own webhook secret, which they legitimately possess.

### Recommendation
Verify the webhook signature using the secret associated with the *same* organization implied by `repository.full_name` (the value handlers actually act on), not a separately-read `owner.login`/`organization.login` field. Alternatively, after selecting the `webhook_secret` for verification, assert that `repository.owner.login` (or `organization.login`) matches the owner segment of `repository.full_name` before any handler runs, rejecting the request (422) on mismatch.

### Proof of Concept
1. Attacker creates their own GitHub org `attacker-org`, installs/configures the Shipit GitHub App for it, and Shipit stores a `webhook_secret` for `attacker-org` (a normal, unprivileged setup step).
2. Attacker computes `sha1=HMAC(webhook_secret_attacker_org, body)` over a crafted push payload body where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `ref = "refs/heads/master"`, `after = "<attacker-chosen sha>"`
3. POST this body to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"` [2](#0-1) , fetches `attacker-org`'s `webhook_secret`, and the HMAC check passes [1](#0-0) .
5. `PushHandler#process` (via inherited `Handler#stacks`/`repository_name`) looks up `Repository.from_github_repo_name("victim-org/victim-repo")` [4](#0-3) [5](#0-4)  and calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived victim `Stack` on that branch, despite the request only ever being authenticated against `attacker-org`'s secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

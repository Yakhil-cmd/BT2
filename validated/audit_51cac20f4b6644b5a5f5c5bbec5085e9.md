### Title
Webhook signature is verified against `repository.owner.login`, but stack/status writes are keyed on the independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App secret to validate `X-Hub-Signature` using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). However, the actual data written by handlers — which repository/stack gets synced (`PushHandler`) or which commit gets a status (`StatusHandler`) — is resolved from a completely different, independently-controlled JSON field: `repository.full_name`, via `Handler#repository_name` and `Repository.from_github_repo_name`. Nothing enforces that the owner segment of `full_name` matches `repository.owner.login`.

### Finding Description
The controller's authentication step is: [1](#0-0) [2](#0-1) 

`verify_signature` picks the HMAC secret with `Shipit.github(organization: repository_owner)` where `repository_owner` comes from `repository.owner.login`, and validates the raw payload bytes against that secret via `GithubApp#verify_webhook_signature`: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches the *entire* payload to event handlers unchanged: [4](#0-3) 

Handlers such as `PushHandler` and `StatusHandler` resolve the target `Stack`/`Repository`/`Commit` using `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a separate field from `repository.owner.login` used for signature verification: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` does a raw string split/lookup of `full_name`, with no cross-check against the owner field used for authentication: [7](#0-6) 

This exactly matches the analog class called out in scope: "an organization that authenticated versus the repository that is written." The equality the code assumes but does not enforce is:
`organization_that_signed(payload.repository.owner.login) == organization_that_owns(payload.repository.full_name)`

Because the HMAC only proves the payload bytes were produced by whoever holds the secret for the organization named in `repository.owner.login`, and does not bind that organization to the repository actually acted upon (`full_name`), an attacker who controls (or is a legitimate integrator for) Organization A's GitHub App/webhook secret can send a webhook where `repository.owner.login = "orgA"` (so verification succeeds, using a secret they legitimately know) while `repository.full_name = "orgB/some-repo"` (so the handler acts on a Stack belonging to an entirely different, unrelated organization/repository that Organization A has no rights over).

### Impact Explanation
This allows cross-repository/cross-organization writes: a party who is only authorized to send webhooks for repository/organization A can forge push and status events that are processed as if they came from organization B's repository, e.g. triggering `stack.sync_github` on B's stacks (`PushHandler`) or attaching fabricated commit statuses to B's commits (`StatusHandler`). This is an unauthorized cross-repository write/deploy trigger — matching the Critical impact bucket ("cross-repository writes, or an unauthorized deploy, rollback or merge") since `sync_github` can affect what commits are considered deployable and can be chained into triggering deploys on stacks the attacker's organization does not own.

### Likelihood Explanation
Exploitability requires only the ability to produce a validly-signed webhook for *any* one organization configured in Shipit (i.e., being a legitimate GitHub App/webhook holder for org A, which is a normal, unprivileged-from-Shipit's-perspective position for anyone controlling org A's own GitHub App settings) plus knowledge of the target repository's `full_name` (public information). No Shipit session, API token, or privileged Shipit account is needed — only crafting the JSON body and computing the correct HMAC with a secret the attacker already legitimately possesses for their own organization. This is a straightforward, repeatable forgery.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), after signature verification succeeds, enforce that the repository the handler will act on (`repository.full_name`'s owner segment) matches the organization used to select/validate the signing secret (`repository.owner.login` / `organization.login`). Reject the webhook (422) if they diverge, e.g.:
```ruby
def verify_signature
  ...
  head(422) unless verified && repository_owner_matches_full_name?
end

def repository_owner_matches_full_name?
  full_name_owner = params.dig('repository', 'full_name')&.split('/')&.first
  full_name_owner.nil? || full_name_owner.casecmp?(repository_owner)
end
```

### Proof of Concept
1. Attacker legitimately controls/administers a GitHub App installation for `org-a` and therefore knows `org-a`'s `webhook_secret`.
2. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(org-a secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature against the attacker-controlled `org-a` secret.
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which calls `stacks` → `Repository.from_github_repo_name("org-b/victim-repo")` and, if such a stack is not archived and matches the branch, invokes `stack.sync_github(expected_head_sha: "deadbeef...")` on `org-b`'s stack — an action the attacker had no authorization to trigger.

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

### Title
Webhook signature verification selects the secret using an unverified `repository.owner.login` field while every event handler acts on the unverified `repository.full_name` field, letting a valid webhook secret for one configured GitHub organization authorize writes against stacks belonging to a different configured organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which per-organization `webhook_secret` to validate the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body, before the signature has been checked. [1](#0-0) [2](#0-1)  Every event handler, however, resolves the target `Stack`/`Repository` using a completely different field of that same unverified body: `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`. [3](#0-2)  Because the HMAC covers the raw request body and is verified with the secret belonging to whichever `owner.login` the attacker chooses to put in the payload, an attacker who legitimately controls one organization's Shipit GitHub App (and therefore knows that organization's `webhook_secret`) can sign a payload where `repository.owner.login` = their own org but `repository.full_name` = `victim-org/victim-repo`. The signature check passes (it's a valid signature for the attacker's own org's secret over the attacker's own byte-for-byte payload), yet the push/status/check_suite handlers act on the victim organization's stack.

### Finding Description
The binding that should hold is: **organization whose secret authenticated the request == organization of the repository being written to**. Shipit supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret`, as documented in `config/secrets.development.example.yml` and `docs/setup.md`. [4](#0-3)  All these organizations' webhooks POST to the same `/webhooks` endpoint, handled by `WebhooksController#create`. [5](#0-4) 

`verify_signature` determines which app/secret to use for verification via:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

This value comes straight from the JSON body before any signature has been validated - the signature validation only proves the body was signed with *some* configured organization's secret matching whatever `owner.login` the body itself claims.

Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers such as `PushHandler`, `StatusHandler`, and `CheckSuiteHandler`. [5](#0-4)  These handlers never look at `repository.owner.login` again; they resolve the affected stacks solely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler#process` then triggers `stack.sync_github`, `CheckSuiteHandler#process` schedules check-run refreshes, and `StatusHandler#process` writes commit statuses directly from `Commit.where(sha: params.sha)` with no repository/organization scoping at all. [6](#0-5) [7](#0-6) [8](#0-7) 

So the two fields used by (a) signature-secret selection and (b) target-resolution are independent, attacker-controlled fields inside a single HMAC-signed blob that the attacker fully composes themselves. Signing "your own org's name plus someone else's repository" with your own legitimately-held secret produces a signature that Shipit accepts as fully authentic, while the effect lands on the victim org's stack.

### Impact Explanation
An attacker who is a legitimate administrator/owner of Organization A (one of potentially several organizations configured on a shared Shipit instance, each with independent GitHub Apps/webhook secrets as per the documented multi-org config) can:
- Forge `push` webhooks that make Shipit believe Organization B's repository has new commits, causing `GithubSyncJob`/`sync_github` to run and, on stacks with `continuous_deployment: true`, trigger an **unauthorized deploy** of a fabricated `after` SHA against Organization B's stack.
- Forge `status` webhooks to flip CI status/`create_status_from_github!` on Organization B's commits, which can be used to unblock deploy safety checks (`required_statuses`) that gate deploys.
- Forge `check_suite` webhooks to fake check-run completion, again defeating deploy gating on Organization B's stacks.

This crosses an organizational trust boundary the multi-tenant webhook secret design is explicitly meant to enforce, and the resulting effect (triggering an unauthorized deploy on another org's stack) falls squarely within the specified Critical impact category ("cross-repository writes, or an unauthorized deploy").

### Likelihood Explanation
Requires only: (1) Shipit configured for more than one GitHub organization (documented, supported configuration), and (2) the attacker being a legitimate administrator of any one of those organizations - not a privileged Shipit user, not requiring any secret belonging to the victim, no session, no `ApiClient` token, and no interception. The attacker never needs to see the victim org's secret; they only need their own, which they already legitimately hold. This is a code-level logic flaw (mismatched fields used for authentication vs. authorization decision), not a probabilistic or environmental condition, so likelihood is high whenever the multi-org feature is used.

### Recommendation
After verifying the signature, re-derive the organization actually being trusted from the *same* field used for authentication, and cross-check it against `repository.full_name`'s owner before dispatching to handlers - i.e., require `repository.full_name.split('/').first == repository_owner` (or resolve the target `Repository`/`Stack` and assert its `owner` matches the organization whose secret validated the signature) before any handler acts on the payload. Alternatively, bind the webhook secret lookup and the target-repository resolution to a single verified identifier so the two can never diverge.

### Proof of Concept
1. Shipit is configured (per `docs/setup.md` / `config/secrets.development.example.yml`) with two organizations: `attacker-org` (secret `S_A`, known to the attacker who owns that GitHub App) and `victim-org` (secret `S_V`, unknown to the attacker), both with Shipit stacks for repositories they own.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already present as a commit on victim stack>",
  "repository": {
    "owner": {"login": "attacker-org"},
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` themselves, since they legitimately know `S_A`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies the HMAC against `S_A` - it matches, because the attacker generated both the message and the signature with their own known secret. [1](#0-0) 
6. `PushHandler#stacks` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")`, and `stack.sync_github(expected_head_sha: ...)` runs against the victim's stack. [3](#0-2) [6](#0-5) 
7. If `continuous_deployment` is enabled on the victim stack, this results in an unauthorized deploy triggered entirely by an attacker who only ever possessed their own organization's webhook secret.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

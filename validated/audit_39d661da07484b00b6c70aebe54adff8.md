### Title
Webhook signature-verification organization is not bound to the payload's target repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) is used to validate the `X-Hub-Signature` HMAC based on `repository_owner`, but the individual webhook handlers select which `Repository`/`Stack` to mutate based on a *different* field read from the same attacker-controlled JSON body. Nothing ties the two together, so in a multi-organization Shipit deployment, a valid signature computed with one organization's secret can be used to make handlers act on a completely different organization's repository/stack.

### Finding Description
Signature verification uses: [1](#0-0) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```
and [2](#0-1) 
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This `repository_owner` value determines *only* which org's `webhook_secret` is used to compute the HMAC — it is never checked against the record that is actually acted upon.

The dispatched handlers instead resolve the target repository/stack independently, from `payload.dig('repository', 'full_name')`: [3](#0-2) 
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Because the whole `params` hash comes from the same attacker-supplied JSON body (`JSON.parse(request.raw_post)`), and the code never asserts `repository.full_name.start_with?("#{repository.owner.login}/")` nor that the signature-selected organization equals the organization that owns the target repository, an attacker who legitimately controls a GitHub App/organization already configured in Shipit (i.e., knows that org's own `webhook_secret`, as configured in `secrets.yml`'s documented multi-org layout) can:

1. Craft a JSON payload where `repository.owner.login` (or top-level `organization.login`) is set to their own org — the value used to select the verification secret.
2. Set `repository.full_name` inside the same `repository` object to `victim-org/victim-repo` — the value the handler uses to look up `Repository`/`Stack`.
3. Sign the raw body with their own known `webhook_secret` for their org.

`verify_signature` will pass because it fetches the GitHub App config for the attacker's own org and validates the HMAC against the attacker's own secret over the exact bytes the attacker chose. The dispatched handler (e.g. `PushHandler`, `CheckSuiteHandler`) then resolves `stacks` for `victim-org/victim-repo` and acts on it: [4](#0-3) 
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
```

This breaks exactly the binding the task calls out: "an organization that authenticated versus the repository that is written." The equality that should hold is `verification_org == owner(target_repository)`, but the code only enforces `verification_org == payload["repository"]["owner"]["login"]`, a field fully independent of `payload["repository"]["full_name"]`, which is what actually selects the mutated `Repository`/`Stack`.

### Impact Explanation
This allows a cross-tenant/cross-organization write: an attacker who is a legitimate owner of one org configured in Shipit (and therefore knows that org's own webhook secret) can trigger handlers to act as if the event came from a different organization's repository. Concretely:
- `PushHandler` enqueues `GithubSyncJob` with an attacker-chosen `expected_head_sha` for a victim's stack, causing Shipit to record an arbitrary "synced" HEAD for that stack.
- `CheckSuiteHandler` / `StatusHandler` can inject arbitrary CI/commit statuses and check-run refreshes onto a victim's commits, corrupting the commit-status data Shipit relies on to gate deploys/merges.

This is a cross-repository/cross-organization data integrity violation achieved purely by forging a webhook body, which corresponds to the "cross-repository writes" high/critical-impact category defined in the rules, since it lets an attacker who only controls one organization's webhook secret write state belonging to a different organization's repository that they do not own or have write access to.

### Likelihood Explanation
This only applies to installations that configure multiple GitHub organizations under `Shipit.github` (each with its own `webhook_secret`), which is a documented, supported configuration (`config/secrets.development.example.yml` shows the multi-org schema). In that scenario, any tenant/organization owner who administers their own GitHub App configuration (and thus knows their own `webhook_secret`) — a routine, expected level of access in a multi-tenant setup — can exploit this without needing repository write access, a Shipit session, or an `ApiClient` token. The exploit requires no privileged Shipit account, matching the "unprivileged attacker" scope of this analysis.

### Recommendation
After parsing the payload, validate that the resolved target repository's owner matches the organization whose secret verified the signature, e.g. assert `payload.dig('repository','full_name')&.split('/')&.first&.casecmp?(repository_owner)` before dispatching to handlers, or derive `repository_owner` consistently from the same field (`full_name`) that handlers use to resolve the `Repository`/`Stack`, so the verification and mutation targets can never diverge.

### Proof of Concept
Given a Shipit instance configured with two orgs:
```yaml
github:
  attacker-org:
    webhook_secret: "attacker_known_secret"
  victim-org:
    webhook_secret: "victim_secret_attacker_does_not_know"
```
1. Attacker (who administers `attacker-org`'s GitHub App and therefore knows `attacker_known_secret`) crafts a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
2. Compute `sha1=HMAC-SHA1(attacker_known_secret, raw_body)` and set as `X-Hub-Signature`.
3. `POST /webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), verifies successfully against the attacker's own secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack with the attacker-supplied `after` SHA — a write to a repository/stack the attacker does not own, authenticated only by the attacker's own organization's credentials.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

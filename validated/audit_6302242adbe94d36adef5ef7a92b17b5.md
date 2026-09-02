### Title
Cross-Organization Webhook Confusion: Signature Verified Against `repository.owner.login`'s Secret While Actions Are Dispatched Against `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound GitHub webhook using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` of the *unverified* JSON body. Once verification passes, the event handlers (e.g. `PushHandler`) look up the target `Stack`/`Repository` using an entirely different, also-unverified field of the same payload: `payload.dig('repository', 'full_name')`. This breaks the equality "organization that authenticated == repository that is written," letting an attacker with knowledge of (or without) one organization's webhook secret forge a signature that is checked only against that organization, while making the handler act on a repository belonging to a different organization.

### Finding Description
The webhook signature check is: [1](#0-0) [2](#0-1) 

`repository_owner` is picked from the payload's `repository.owner.login` (attacker-controlled field, sent before verification), and used to pick the `GitHubApp` (and its `webhook_secret`) via `Shipit.github(organization: repository_owner)`: [3](#0-2) 

The actual signature check is a straightforward HMAC-over-raw-body compare against that organization's `webhook_secret`: [4](#0-3) 

Critically, if the selected organization has no `webhook_secret` configured, verification is skipped entirely (`return true unless webhook_secret`) — see `docs/setup.md`/`secrets.*.yml` samples showing `webhook_secret: # nil` is an accepted, documented configuration for individual orgs in a multi-org setup.

Once `verify_signature` passes, `WebhooksController#create` dispatches the *entire, unverified* payload to handlers: [5](#0-4) 

Handlers resolve the target `Stack` using a **different** field of the same payload — `repository.full_name` — not `repository.owner.login`: [6](#0-5) 

For example, `PushHandler` uses this to find all stacks tracking the branch and enqueue a GitHub sync: [7](#0-6) 

Because `repository.owner.login` (used to select/verify the secret) and `repository.full_name` (used to select the acted-upon repository/stack) are two independent, attacker-supplied fields inside the same unauthenticated JSON body, there is no cross-check binding them together. An attacker who controls or knows the webhook secret for organization A (or for any organization configured with `webhook_secret: nil`) can submit a payload where `repository.owner.login = "org-a"` (so the signature check passes against org A's secret) but `repository.full_name = "org-b/victim-repo"` (so the handler acts on org B's stack).

### Impact Explanation
This allows an unprivileged external attacker (anyone who can reach the public `/webhooks` endpoint, no Shipit session, GitHub write access, or private key required) to inject events for organizations/repositories they do not control, as long as any single organization in the Shipit deployment has a discoverable/knowable webhook secret or no secret configured at all. Concretely this enables:
- Forcing `GithubSyncJob` enqueues for arbitrary victim stacks via `push` events (`PushHandler`).
- Forging commit `status` events (`StatusHandler`) and `check_suite` events (`CheckSuiteHandler`) against victim repositories/commits, which the deployment-check/continuous-delivery machinery consults when deciding whether a stack is safe to auto-deploy (`Stack#sync_github`, continuous delivery scheduling). Forged green statuses/checks could push a victim stack through automated deploy criteria it should not satisfy.
- Manipulating pull-request-related handlers (`app/models/shipit/webhooks/handlers/pull_request/*`) for a victim repository/stack.

This crosses the "unauthorized deploy" bar in the rules to the extent that forged CI status/check-suite state can influence continuous delivery decisions on a stack the attacker does not own, and at minimum is an authentication-bypass of the webhook trust boundary (organization the signature authenticates ≠ repository the engine acts on).

### Likelihood Explanation
Exploitability depends on the deployment having more than one organization configured (multi-org `github:` config keyed by org, as shown in `config/secrets.development.shopify.yml` and `docs/setup.md`), and either (a) an organization with `webhook_secret` unset (explicitly supported/documented as `# nil`), or (b) the attacker being a legitimate GitHub App/webhook owner for one configured org while targeting another org's stack in the same Shipit instance. This is a realistic misconfiguration/multi-tenant scenario the engine's own code supports out of the box, not a "host application not mounting the engine as documented" case.

### Recommendation
After parsing the payload, verify that the organization/owner used to select the verification secret matches the owner embedded in `repository.full_name` (or `organization.login`) before dispatching to handlers, and reject payloads where they differ. Alternatively, always resolve the `Repository`/`Stack` first through a trusted, single canonical field, and select the webhook secret using that same resolved organization rather than trusting two independently-forgeable fields.

### Proof of Concept
1. Shipit is configured with two GitHub orgs: `org-a` (attacker has/knows `webhook_secret`, or it is unset) and `org-b` (victim, has a stack tracked in Shipit).
2. Attacker computes body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a webhook_secret, body)>` (or sends no valid signature at all if `org-a` has `webhook_secret: nil`, since `verify_webhook_signature` then returns `true` unconditionally).
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` looks up `repository_owner = "org-a"`, verifies against `org-a`'s secret — passes.
6. `PushHandler` resolves `repository_name = "org-b/victim-repo"` via `Repository.from_github_repo_name` and enqueues `GithubSyncJob` for `org-b`'s stack(s), despite the request never being authenticated by anything belonging to `org-b`.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

### Title
Webhook signature verification is keyed on an attacker-controlled `repository.owner.login`/`organization.login` field, letting a forged payload authenticate as one GitHub organization while writing to a different organization's repository/stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `GitHubApp` (and therefore which `webhook_secret`) to use for HMAC verification based on a value read straight out of the untrusted, attacker-supplied JSON body, while the actual `Shipit::Webhooks::Handlers::Handler` subclasses that execute the write path resolve the target `Repository`/`Stack` from a *different, independently attacker-controlled* field of the same body (`repository.full_name`). Nothing ties the two together, so the organization that "authenticates" the request is not guaranteed to be the organization whose repository is actually acted upon.

### Finding Description
`verify_signature` picks the signing organization like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`repository_owner` is read from the raw JSON body the attacker fully controls before any signature is checked. `Shipit.github(organization:)` looks up a per-organization config (`app_id`, `webhook_secret`, etc.) that operators are told is optional per organization: [4](#0-3) 

and `verify_webhook_signature` is a no-op when that organization has no secret configured: [5](#0-4) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Meanwhile, every event handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, `LabelCapturingHandler`, etc.) resolves the repository/stack to act on purely from `payload.dig('repository', 'full_name')`, via the shared base class: [6](#0-5) 

or an equivalent direct lookup in `LabelCapturingHandler`: [7](#0-6) 

Because `repository.owner.login` (used for signature-org selection) and `repository.full_name` (used to resolve the actual `Repository`/`Stack`) are two independent JSON fields in the same forged body, an attacker can set them inconsistently: claim the request originates from organization *A* (which has no `webhook_secret` configured, or whose secret the attacker otherwise controls) while pointing `repository.full_name` at a real repository belonging to organization *B* (a properly protected org). `verify_signature` authenticates against org A's (absent) secret and passes trivially, then the handler acts on org B's `Stack`, e.g. triggering `stack.sync_github` from `PushHandler`, `schedule_refresh_check_runs!` from `CheckSuiteHandler`, commit status writes from `StatusHandler`, or pull-request/review-stack state changes from `LabelCapturingHandler`.

This is exactly the "organization that authenticated vs. repository that is written" trust binding: the equality `organization_used_for_signature == organization_owning_written_repository` is assumed but never enforced.

### Impact Explanation
An unprivileged, external attacker who can reach the `/webhooks` endpoint (a public endpoint by design, since GitHub calls it unauthenticated aside from the HMAC signature) can inject GitHub events attributed to a repository/stack in an organization they were never authorized to touch, as long as any organization configured on the Shipit instance has no `webhook_secret` (an explicitly documented "optional" configuration) or a guessable one. Depending on which handler is reached, this can:
- Force `PushHandler` to invoke `stack.sync_github(expected_head_sha:)` against an arbitrary target `Stack`, which can feed into continuous-delivery sync logic and downstream deploy scheduling.
- Poison commit statuses via `StatusHandler#process` → `commit.create_status_from_github!`, potentially influencing whether a commit is considered deployable.
- Manipulate pull-request/review-stack lifecycle state via `LabelCapturingHandler`, which drives review-stack provisioning.

Given that these actions can influence deploy/rollback decisioning for a repository the attacker does not own, this rises to the "unauthorized deploy" class of High/Critical impact described in the engine's threat model, contingent on the deployment operator's multi-org configuration (some orgs unsecured, others secured).

### Likelihood Explanation
Likelihood is conditioned on a specific but realistic and *documented* configuration: Shipit explicitly supports multiple GitHub organizations each with their own `webhook_secret`, and the setup guide calls the webhook secret "optional." Any operator following the documented multi-tenant setup while leaving one organization's secret blank (or where that organization's secret leaks) enables this cross-organization forgery against every other, properly-secured organization's stacks on the same instance. No repository write access, GitHub App key, or Shipit session is required — only the ability to POST JSON to the public `/webhooks` endpoint.

### Recommendation
- Do not select the verification organization from attacker-controlled payload fields ambiguously; require that the resolved `Repository` (by `full_name`) belongs to the same organization used to select/verify the webhook secret, and reject the event otherwise.
- Alternatively, verify the signature against every configured organization's secret (or a global secret) rather than a payload-selected one, and require that all configured organizations have a `webhook_secret` set (fail closed if not, rather than `return true unless webhook_secret`).
- After signature verification, re-derive `repository_owner` strictly from the verified organization and cross-check it against `repository.full_name`'s owner segment before allowing any handler to write to that stack/repository.

### Proof of Concept
Given a Shipit instance configured with two organizations, where `orgA` has no `webhook_secret` and `orgB` has a `Stack` for `orgB/prod-app`:

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   # irrelevant, org A has no secret

{
  "ref": "refs/heads/master",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/prod-app"
  }
}
```

`verify_signature` computes `repository_owner` = `"orgA"`, looks up `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (bogus) `X-Hub-Signature`. `PushHandler#process` then resolves `Repository.from_github_repo_name("orgB/prod-app")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on `orgB`'s real stack — a write performed on behalf of an organization the request never actually authenticated as.

*Note: I was unable to fully trace `Stack#sync_github`'s downstream effects (e.g., whether it can autonomously trigger a deploy vs. only fetch commits) within the available index; a background Devin session with full repository access would be needed to confirm the exact severity ceiling (unauthorized deploy vs. state corruption only) of the `sync_github` call path.*

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

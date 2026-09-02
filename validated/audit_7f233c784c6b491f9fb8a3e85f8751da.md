## Analysis

I found a concrete deployment-trust binding break in this codebase, analogous to the report's core lesson (a state-changing action authorized using data that isn't actually validated). It doesn't involve re-entrancy per se, but it breaks the same class of invariant: **the organization whose GitHub App credentials authenticate a webhook is derived from the same unverified payload that later selects the repository/stack to act on.**

`WebhooksController#verify_signature` picks the signing secret to check against using `repository_owner`, a value read straight from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` / `params.dig('organization', 'login')`), before the signature has been validated: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization config in the multi-app setup [3](#0-2) , and `GitHubApp#verify_webhook_signature` **unconditionally returns `true` when the resolved organization's `webhook_secret` is blank**: [4](#0-3) 

Meanwhile, the actual target of the webhook (which `Stack`/`Repository` gets mutated) is derived from a *different* field of the same unverified payload — `payload.dig('repository', 'full_name')` in `Handler#repository_name` / `#stacks`: [5](#0-4) 

Because `repository.owner.login` (used to select which secret authenticates the request) and `repository.full_name` (used to select which repository/stack the handler operates on) are independent, attacker-controlled fields in the same forged JSON body, an attacker can craft a payload where `repository.owner.login` names an organization configured in `secrets.github` with **no `webhook_secret` set** (this is an explicitly supported, documented configuration — see `config/secrets.development.example.yml` and `docs/setup.md`'s "Using Multiple Github Applications" section) while `repository.full_name` names a *different, secured* organization's repository that has real stacks in Shipit. This satisfies "an organization that authenticated versus the repository that is written" — the two are never bound to each other or cryptographically tied to the actual signature.

## Impact

With signature verification trivially bypassed for the attacker-chosen `repository.owner.login`, an unauthenticated party can submit forged webhook events (`push`, `status`, `pull_request`, `check_suite`, etc.) that are dispatched to handlers acting on the repository named by `repository.full_name` — a different, legitimately-configured org/repo. Depending on which handler is invoked (`PushHandler`, `StatusHandler`), this can create/update commits, alter commit statuses, or otherwise manipulate stack state used to gate deploys — a step toward an unauthorized deploy/merge decision, without possessing any valid `webhook_secret`, `ApiClient` token, or repository access.

## Uncertainty

I was not able to fully read `push_handler.rb` and `status_handler.rb` contents (only grep hits were returned) to confirm exactly which state-changing operations follow from a forged payload once past `verify_signature`, nor whether every deployment relies on the single-org fallback (`github_default_organization`) instead of the multi-org path in practice. This determines the full blast radius (e.g., whether it can actually flip a `commit_status` used as a deploy gate, per `Shipit::Hook::EVENTS` including `commit_status`/`merge_status`). A background Devin session with full file access would be needed to trace `PushHandler#process` and `StatusHandler#process` to confirm the exact mutating side effects and whether they can influence `Stack#branch_status`/`merge_status` (and thus deploy eligibility) for a targeted stack.

Given this uncertainty on the precise mutating consequence required to hit the "Critical/High impact" bar (unauthorized deploy vs. unauthenticated read/write of stack state), I present this as the strongest reachable analog but flag it as needing handler-level confirmation before treating it as fully proven Critical/High impact.

### Title
Webhook signature verification keyed off unverified payload field allows org/secret confusion - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret using `repository_owner`, a value taken from the same unverified JSON body it is meant to authenticate, and `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that organization has no `webhook_secret` configured — a supported configuration for multi-org Shipit deployments.

### Finding Description
The equality that should hold is: *the organization whose credentials authenticate the webhook == the organization that owns the repository being mutated by the webhook.* Instead, both values come from attacker-controlled JSON fields (`repository.owner.login` vs `repository.full_name`) that are never cross-checked, and are read before any cryptographic verification occurs [6](#0-5) . If the attacker names an organization in the multi-app config that has `webhook_secret: nil` (a documented, valid setup shown in `config/secrets.development.example.yml:8-16` and `docs/setup.md:182-209`), `verify_webhook_signature` returns `true` unconditionally regardless of the actual `X-Hub-Signature` header [4](#0-3) . The request then proceeds to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [7](#0-6) , and handlers resolve the target `Stack` from the unrelated `repository.full_name` field [5](#0-4) .

### Impact Explanation
An unauthenticated attacker can forge webhook deliveries that are accepted as "verified" for any repository whose owning org happens to lack a `webhook_secret`, while the payload's `repository.full_name` targets a fully-configured, unrelated stack. This lets forged `push`/`status`/`pull_request` events mutate commit/stack state without any credential, undermining the trust boundary the signature check is meant to enforce.

### Likelihood Explanation
Requires the deployment to use the multi-organization `github:` config format with at least one organization lacking `webhook_secret` (explicitly documented as supported) — plausible in real-world multi-tenant Shipit installs, but not universal, hence conditional rather than guaranteed exploitability for every deployment.

### Recommendation
Never select the verification secret using unverified request data. Verify the raw signature against every configured organization's secret (or a single well-known secret) independently of any payload-derived organization name, and reject the request if no configured secret validates it — do not treat "no secret configured for the attacker-chosen org" as an implicit pass.

### Proof of Concept
1. Configure Shipit with the documented multi-org format where `OrgA` has a real `webhook_secret` and stacks, and `OrgB` is configured with `webhook_secret: nil`.
2. POST to `/webhooks` with `X-Github-Event: push`, no valid `X-Hub-Signature`, and body `{"repository": {"owner": {"login": "OrgB"}, "full_name": "OrgA/real-repo"}, ...push payload fields...}`.
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `verify_webhook_signature` returns `true` because `webhook_secret` is blank [8](#0-7) .
4. `PushHandler` (invoked via `Shipit::Webhooks.for_event('push')`) resolves the target stack via `Repository.from_github_repo_name("OrgA/real-repo")` [5](#0-4)  and processes the forged event against `OrgA`'s real stack, with no valid credential ever presented.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

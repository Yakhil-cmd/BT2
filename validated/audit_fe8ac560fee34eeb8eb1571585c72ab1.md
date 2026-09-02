### Title
Missing `webhook_secret` for any configured GitHub org silently disables webhook signature verification, allowing unauthenticated PR mutation - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for an organization, and `WebhooksController#verify_signature` treats this as a valid signature. If any org in `Shipit.github` config (e.g. "OrgC") omits `webhook_secret` — which the setup docs explicitly mark as *optional* — an attacker can POST unsigned/garbage webhook payloads that reach handlers like `AssignedHandler#process`, mutating real `Shipit::PullRequest` records for that org without any authentication.

### Finding Description
The claimed binding is: `verify_signature-returns-true` should imply `HMAC(webhook_secret, raw_body) == provided_signature`. In practice: `verify_webhook_signature` at [1](#0-0)  executes `return true unless webhook_secret` before ever inspecting the signature header or body, so when `@webhook_secret` (set from `@config[:webhook_secret].presence` at [2](#0-1) ) is blank, the method is vacuously true regardless of the `X-Hub-Signature` value or body content.

`WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner).verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` and only rejects with 422 if `verified` is falsy: [3](#0-2) . `repository_owner` is taken directly from attacker-controlled JSON body (`params.dig('repository','owner','login')`) [4](#0-3) , and `Shipit.github` looks up the per-organization config via `github_app_config(organization)` [5](#0-4) . Multi-org setups are an explicitly documented and supported configuration shape in `docs/setup.md` (Using Multiple Github Applications section), where `webhook_secret` is listed but not enforced as required.

If the request passes `verify_signature`, `WebhooksController#create` dispatches to registered handlers with the raw parsed JSON: [6](#0-5) . `AssignedHandler#process` then does `pull_request.update(github_pull_request: params.pull_request) if pull_request.present?` for a `Shipit::PullRequest` located purely by repository full_name and PR number from the payload, with no ownership/auth check beyond the (bypassed) signature verification: [7](#0-6) .

No other guard intervenes: `drop_unhandled_event` only screens for handler-registered event types, `check_if_ping` only special-cases the ping event, and there is no `ExplicitParameters` schema check that validates authenticity — schemas only validate shape of attacker-supplied JSON, not its provenance. Thus the equality `signature-verified == HMAC-checked` does not hold whenever an org's `webhook_secret` is unset, and the divergence is not caught anywhere else in the pipeline.

### Impact Explanation
An attacker who knows (or guesses/enumerates) an organization name configured in a multi-org Shipit deployment without a `webhook_secret` can forge arbitrary webhook events for that org's repositories — not just `pull_request.assigned`, but any handler registered under `Shipit::Webhooks` (e.g. push, status, check_run handlers), since the same `verify_signature` before_action gates the entire `WebhooksController#create` action. This is a real authentication bypass: an unauthenticated third party can write to `Shipit::PullRequest` records (and potentially other stack/commit state depending on which handlers are registered) for a repository they do not own, with no valid GitHub signature required. Blast radius is scoped to whichever org(s) are misconfigured without a secret, but repeatable indefinitely per request.

### Likelihood Explanation
This requires a specific configuration precondition: a Shipit deployment using the multi-org `github` config format (documented in `docs/setup.md`) where at least one organization's `webhook_secret` key is left blank/absent — the docs mark it "(optional)" for the single-org case and don't flag it as mandatory in the multi-org example either. Given the docs literally show `webhook_secret:` as an empty template value in the multi-org example and describe it as filled in "if you've set a webhook secret," an operator following the docs without deliberately generating a secret for every org would leave this open. No secrets, sessions, or GitHub credentials are needed by the attacker — only knowledge of an affected org's login name and a real `Shipit::PullRequest`/repository record to target, both of which are plausibly discoverable (GitHub org/repo names are public).

### Recommendation
Change `verify_webhook_signature` to fail closed instead of open when `webhook_secret` is blank — e.g. log/raise a configuration error and reject the webhook (`return false unless webhook_secret`), and/or enforce `webhook_secret` as a required config key (add to a required-keys check, or validate presence at `GitHubApp.new`/boot time) rather than treating it as optional. Update `docs/setup.md` to state that `webhook_secret` is mandatory for every configured organization.

### Proof of Concept
Minitest plan (no live GitHub required):

1. Unit test in `test/lib/shipit/github_app_test.rb`:
   ```ruby
   test "verify_webhook_signature returns true with no secret configured, even with garbage signature" do
     app = Shipit::GitHubApp.new('OrgC', {}) # no webhook_secret key
     assert app.verify_webhook_signature('sha1=deadbeef', '{"garbage":true}')
     assert app.verify_webhook_signature(nil, '{"garbage":true}')
   end
   ```
   Assert LHS (`verify_webhook_signature` result) == `true` while RHS (`OpenSSL::HMAC.hexdigest` of any real secret against the body) is undefined/never computed — demonstrating the binding is broken.

2. Integration test in `test/controllers/webhooks_controller_test.rb`:
   - Stub `Shipit.github(organization: 'OrgC')` (or configure `secrets.github['orgc']` with `webhook_secret: nil`) to return a `GitHubApp` without a secret.
   - Create a real `Shipit::PullRequest` belonging to a stack on a repository owned by `OrgC`.
   - POST to `/webhooks` with header `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature` header (or omit it), and a JSON body matching `AssignedHandler`'s schema (`action: "assigned"`, matching `number`, `repository.full_name`, etc.).
   - Assert response is `200 OK` (not `422`), and assert the `PullRequest` record's `github_pull_request` attribute was updated to the forged payload — proving `AssignedHandler#process` executed `pull_request.update` with zero valid authentication.

### Citations

**File:** lib/shipit/github_app.rb (L50-50)
```ruby
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

Now I have enough to confirm the vulnerability path. Key facts confirmed:

- `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC against based on `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) .
- `Shipit.github(organization:)` looks up per-organization app config (`app_id`, `webhook_secret`, etc.) in a multi-org deployment (`config/secrets.development.shopify.yml` shows this multi-org schema) [3](#0-2) [4](#0-3) .
- The `StatusHandler` and other event handlers then act on a **completely different field** of the same payload — `repository.full_name` (via `Handler#repository_name`) for repo/stack lookup, and for `StatusHandler` specifically, on `params.sha`/`params.state` directly, with **no cross-check that the org used for signature verification matches the org owning the target commit/stack** [5](#0-4) [6](#0-5) .
- `StatusHandler#process` writes a `Status` directly from webhook payload fields (state, sha, description, target_url, context) without any GitHub API round-trip verification, and creating that record has real effects: it flips CI state on a `Commit`, which gates deploys, and schedules continuous delivery [7](#0-6) [8](#0-7) .

This maps precisely to the requested binding-break: **"an organization that authenticated versus the repository that is written."** In a multi-organization Shipit deployment, the org used to select/verify the HMAC secret (`repository.owner.login`) is not cryptographically bound to the org/repo whose `Commit`/`Status` is actually mutated (`params.sha`, matched only by global `sha` string across all stacks — `Commit.where(sha: params.sha).each`, with no repository/stack scoping at all).



I have enough evidence to write the final report now.

### Title
Cross-organization Status forgery via webhook signature/target binding break in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
In a multi-GitHub-organization Shipit deployment, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate an inbound webhook's HMAC signature against using a value taken from the **untrusted, not-yet-verified** payload itself (`repository.owner.login` / `organization.login`). Once verification passes for *that* organization's secret, the `status` event handler (`StatusHandler`) never re-checks that the verified organization actually owns the target resource being mutated: it matches and updates `Commit` rows purely by SHA string, with no scoping to the repository/organization whose signature was checked. An attacker who legitimately controls (or knows the webhook secret of) any one organization onboarded onto the same Shipit instance can therefore forge a signed "success" CI status for a commit belonging to a completely different organization's stack.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` from the raw, unauthenticated JSON body and uses it to pick the GitHub App config (and thus `webhook_secret`) to verify against:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [9](#0-8) 

`Shipit.github(organization:)` looks up per-organization secrets (`app_id`, `webhook_secret`, `oauth`, ...) — this is the documented multi-org config schema [3](#0-2) [4](#0-3) .

Once the signature check passes (proving only that *some* org's secret matches the *entire* raw body — a property fully satisfiable by an attacker with legitimate access to any one onboarded org), the event is dispatched to handlers with the raw `params` hash [10](#0-9) .

`StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 

This lookup is **global across all stacks/repositories/organizations** — it is not scoped by `repository.full_name`/`repository_owner` at all, unlike other handlers (e.g. `PushHandler`, `PullRequest` handlers) which do scope via `Handler#stacks`/`repository_name` [5](#0-4) . Creating a `Status` record has direct side effects: it flips the commit's CI state and schedules continuous delivery [11](#0-10) .

**Binding broken:** the organization whose secret authenticated the request ≠ the organization/repository whose `Commit` is written. Nothing in `StatusHandler` re-derives or checks `repository_owner` against `commit.stack.repository.owner`.

### Impact Explanation
An attacker who controls (or has been granted webhook-triggering capability for) one organization onboarded to a shared Shipit instance can forge a valid signature for a `status` payload with an arbitrary `sha` (a public value, trivially obtainable from any target org's public/private GitHub repo they can read) and `state: "success"`, `context: <required-ci-context>`. This injects a fabricated passing CI status for a commit belonging to a **different organization's stack**, satisfying `ci.require` gating and enabling that commit to be deployed via Shipit — i.e., an unauthorized deploy path that crosses an organizational trust boundary the signature check was supposed to enforce. This matches the required impact bar of "an unauthorized deploy" via a cross-organization/cross-repository write.

### Likelihood Explanation
Requires: (a) a Shipit instance configured with multiple GitHub organizations sharing one engine instance (an explicitly documented and supported configuration), and (b) attacker control of a legitimate GitHub App/webhook-secret for at least one of those orgs. Given that constraint, the forgery itself is trivial — a single crafted HTTP POST with a valid HMAC computed from the attacker's own org's secret. No additional privilege inside the target org is needed.

### Recommendation
In `StatusHandler` (and any other handler that doesn't scope through `Handler#stacks`), enforce that the `repository_owner` used for signature verification matches the owning organization of every `Commit`/`Stack` being mutated — e.g., scope `Commit.where(sha: params.sha)` to `stack.repository.owner == repository_owner`, or better, pass the verified `repository_owner` from the controller into the handler and require handlers to filter all lookups by it, matching the pattern already used by `Handler#stacks`/`repository_name`.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `org-attacker` and `org-victim`, each with its own `webhook_secret`.
2. Attacker (owning/administering `org-attacker`'s GitHub App or otherwise possessing its `webhook_secret`) computes a valid `X-Hub-Signature` HMAC-SHA1 using `org-attacker`'s secret over a JSON body:
```json
{
  "sha": "<public sha of a commit in org-victim/some-repo tracked by Shipit>",
  "state": "success",
  "context": "<the ci.require context configured for org-victim's stack>",
  "repository": { "owner": { "login": "org-attacker" } }
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and the computed signature.
4. `verify_signature` resolves `repository_owner` = `"org-attacker"`, verifies against `org-attacker`'s secret — passes.
5. `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the `org-victim` commit (no org check), and creates a `success` `Status` on it — satisfying `ci.require` and unlocking deploy for `org-victim`'s stack, despite the request being authenticated only against `org-attacker`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

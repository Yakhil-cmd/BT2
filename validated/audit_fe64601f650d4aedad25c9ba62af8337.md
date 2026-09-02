### Title
Webhook signature verification is bound to an attacker-chosen organization while event handlers act on an unrelated `repository.full_name` — cross-repository status/state forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's webhook secret to validate an incoming webhook against using a value taken straight from the unauthenticated JSON body (`repository.owner.login` / `organization.login`), while the handlers invoked immediately afterward act on a *different* field of that same body (`repository.full_name`) to decide which `Repository`/`Stack` to mutate. Because these two payload fields are never cross-checked, an attacker who controls a legitimate organization/repo registered in the same Shipit instance (multi-tenant `secrets.github` config) can sign a payload with their own webhook secret while pointing `repository.full_name` at a victim repository, causing the engine to accept forged events (e.g. commit `status`) for a repo the attacker doesn't own.

### Finding Description
`Shipit.github(organization:)` supports a multi-organization configuration keyed by organization name in `secrets.github` [1](#0-0) . `WebhooksController#verify_signature` picks the `GitHubApp`/secret to verify with by reading `repository_owner`, which is derived entirely from the attacker-controlled JSON payload: [2](#0-1) [3](#0-2) 

Once `verify_signature` passes, `create` dispatches the entire raw payload to every registered handler for the event type without any additional binding to the organization that was authenticated: [4](#0-3) 

Every handler, however, resolves the target `Repository`/`Stack` using a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [5](#0-4) 

For example `PushHandler` and `StatusHandler`-style processing use `stacks`/`Repository.from_github_repo_name(repository_name)`, which is driven solely by `full_name`: [6](#0-5) 

The binding that should hold is:
`organization used to select/verify the webhook secret == organization embedded in the repository that handlers subsequently write to`

That binding is not enforced anywhere: `repository_owner` (used for authentication) and `repository.full_name` (used for the actual database mutation) are independent, attacker-supplied strings in the same unauthenticated JSON body. An attacker who legitimately owns an organization configured in the multi-tenant `secrets.github` hash (and thus knows/controls that org's `webhook_secret`) can:
1. Set `repository.owner.login` (or `organization.login`) to their own org, so `Shipit.github(organization: repository_owner)` resolves to their own known secret and `verify_webhook_signature` succeeds.
2. Set `repository.full_name` to `"victim-org/victim-repo"`, an unrelated repository/stack hosted on the same Shipit instance but owned by a different tenant.

The webhook signature is a pure HMAC over the raw body with the secret Octokit/GitHub attaches to whichever organization/app sent it; nothing in `SecureCompare.secure_compare` or `verify_webhook_signature` ties the signature to the specific repository referenced inside the payload [7](#0-6) .

### Impact Explanation
This breaks the "organization authenticated versus repository written" trust binding called out in scope. Depending on which webhook event is forged, the practical impact ranges from state corruption to potentially triggering unauthorized deploy decisions:
- `status` events let an attacker inject fabricated CI/commit statuses onto a victim stack's commits. If that stack's `shipit.yml` declares `ci.require`/`ci.blocking` contexts used to gate autodeploy/merge, forging a passing status for a required context is a step toward an **unauthorized deploy** on a repository the attacker has no access to — squarely in the "High" impact bucket (escalation causing an unauthorized deploy/merge) defined in the rules.
- `push` events can force an unrelated stack to `sync_github` against attacker-chosen expected head SHAs.
- `pull_request`/`membership` events let an attacker manipulate review-stack provisioning or team membership records tied to a repository/org they don't control.

This is only exploitable when Shipit is configured with the multi-organization `secrets.github` schema (i.e., the instance hosts more than one GitHub organization/app, which the code explicitly supports via `github_app_config`/`github_organizations`); this is a legitimate, documented configuration mode of the engine, not a misconfiguration outside the app's control.

### Likelihood Explanation
The webhook endpoint is intentionally unauthenticated (it relies solely on HMAC signature verification, per design) and reachable by anyone who can send an HTTP request. The only requirement is that the attacker control (or register) one organization/app entry within the same multi-tenant Shipit deployment — a realistic scenario for shared/internal Shipit instances serving many teams/orgs, where any onboarded team could forge events against any other team's repositories. No `ApiClient` token, GitHub App private key, or repository write access to the victim's repo is needed, satisfying the "unprivileged attacker" requirement.

### Recommendation
After signature verification, cross-check that the organization used to resolve the webhook secret matches the organization embedded in `repository.full_name` (or `organization.login`) before dispatching to handlers, e.g. reject the request if `repository_owner` (owner-derived) does not equal the owner segment of `repository.full_name`. Alternatively, bind webhook secrets per-repository (not just per-organization) and validate that binding against the exact repository referenced in the payload before any handler runs.

### Proof of Concept
Conceptual (cannot be executed here, no filesystem/terminal access):
1. Configure Shipit with two organizations in `secrets.github`: `attacker-org` (attacker controls the webhook secret, e.g. by registering a webhook on their own GitHub org pointing at the shared Shipit instance) and `victim-org` (hosts a stack with `ci.require` gating autodeploy).
2. Craft a `status` webhook payload JSON:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `sha`, `state: "success"`, `context: "<required-context>"` pointing at a real commit on `victim-org/victim-repo` that is pending deploy.
3. Sign the raw body with `attacker-org`'s known `webhook_secret` and send it as `X-Hub-Signature: sha1=<hmac>` with `X-Github-Event: status` to `POST /webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature validates successfully [8](#0-7) .
5. The `status` handler processes the payload using `repository.full_name` = `victim-org/victim-repo`, writing a forged `Status` for a commit the attacker never had access to [5](#0-4) , potentially satisfying a required CI context and enabling an unauthorized deploy on `victim-org`'s stack.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L26-38)
```ruby
        def process
          raise NotImplementedError
        end

        private

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

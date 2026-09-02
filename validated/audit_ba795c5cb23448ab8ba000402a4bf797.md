### Title
Webhook signature validated against a different GitHub organization than the one whose payload is executed - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to validate the HMAC signature against by calling `repository_owner`, which reads from Rails' `params` (query string + body merged). The actual event processing in `create`, however, re-parses the raw POST body directly (`JSON.parse(request.raw_post)`) and dispatches handlers using the repository/organization named *inside that raw body*. These two "organization" values are not guaranteed to be the same, breaking the required equality: `organization whose secret authenticated the request == organization whose repository is written to`.

### Finding Description
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [2](#0-1) 

`repository_owner` reads from the controller's `params` object, which in Rails is the merge of query-string parameters and JSON-body parameters (query parameters take precedence on key collision). `create`'s local `params` variable, in contrast, is a fresh `JSON.parse` of the raw body only. This means an attacker can send a request to `/webhooks?repository[owner][login]=<org-without-secret>` while keeping a body that is validly signed... or, more importantly, whose `repository.owner.login` is a completely different organization. `verify_signature` will look up `Shipit.github(organization: 'org-without-secret')` and call `verify_webhook_signature`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Per the setup docs, `webhook_secret` is explicitly optional per-organization [4](#0-3) , and the multi-org config schema (`Shipit.github(organization:)` / `github_app_config`) supports several independently configured orgs with independent `webhook_secret` values [5](#0-4) . If any configured organization has a blank `webhook_secret` (a supported, documented configuration), signature verification for that organization trivially returns `true` for any payload/signature pair, regardless of the body's actual content. Since `repository_owner` (used for the security decision) is influenced by request parameters that need not match the body actually dispatched to handlers, the attacker can pick the org whose check is a no-op while the effectively-executed payload targets a different, protected organization/repository, letting them forge that org's webhook events — e.g. fabricate a `status`/`push`/`membership` event for a repository/org they don't control.

Handlers act directly on the dispatched (real body) payload: `StatusHandler` creates commit CI statuses from `params.sha`/`params.state` [6](#0-5) , `PushHandler` triggers a `GithubSyncJob` for the branch in `params.ref`/`params.after` [7](#0-6) , and `MembershipHandler` adds/removes a GitHub login from a `Team` used for `Shipit.github_teams` authorization [8](#0-7) , [9](#0-8) .

### Impact Explanation
This breaks the "organization authenticated vs. repository written" binding called out in the review scope. If it can be exercised (see caveat below), it allows an unauthenticated party to inject fabricated GitHub webhook events (commit statuses, pushes, or team membership changes) against a repository/organization protected by a real `webhook_secret`, which can fake a green CI status enabling an unauthorized deploy, or add an attacker-controlled login to a `Team` counted toward `Shipit.github_teams`, escalating into stack authorization — both are High/Critical-tier impacts per the rules.

### Likelihood Explanation
This is Undetermined/conditional rather than a guaranteed bypass. It requires: (a) confirmation that Rails' request `params` for this JSON-only, POST-only endpoint actually merges/overrides body values with query-string values (this engine sets no explicit `wrap_parameters`/parameter parser override, and Rails' default `ActionDispatch::Http::Parameters#parameters` merges `request_parameters` with `query_parameters`, with query parameters taking precedence on collision, but I could not directly inspect that merge logic in this repository's code — it lives in the Rails framework, not in-scope engine code); and (b) that at least one configured GitHub organization in the deployment has a blank `webhook_secret` (explicitly supported/documented as optional). Absent a misconfigured org with no secret, `verify_webhook_signature` will correctly reject the forged request for any org whose secret the attacker doesn't know, so the exploit is contingent on operator configuration rather than universally exploitable — this weakens confidence versus a hard root-cause proof entirely within engine code.

### Recommendation
- Compute `repository_owner` from the same parsed body object used to dispatch handlers (i.e., parse `request.raw_post` once and use it for both signature-org selection and handler dispatch), never from Rails' merged `params`.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for a multi-org deployment; require every organization entry to configure a secret, or explicitly disallow mixing secretless and secret-protected orgs in the same deployment.
- Add a regression test asserting that query-string-supplied `repository`/`organization` values cannot influence which org's secret is used to validate a webhook whose body targets a different org.

### Proof of Concept
1. Deploy Shipit with multi-org GitHub config where org `A` has a real `webhook_secret` and org `B` has none (`webhook_secret:` left blank, a documented-as-optional setting) [4](#0-3) .
2. Attacker sends: `POST /webhooks?repository[owner][login]=B` with header `X-Github-Event: status`, no valid `X-Hub-Signature` for org A, and JSON body `{"repository":{"owner":{"login":"A"}}, "sha":"<victim-sha>", "state":"success", ...}`.
3. `verify_signature` computes `repository_owner` → `"B"` (from query string) [10](#0-9) , calls `Shipit.github(organization: 'B').verify_webhook_signature(...)`, which returns `true` unconditionally since org B has no `webhook_secret` [3](#0-2) .
4. `create` re-parses the raw body (targeting org A) and dispatches `StatusHandler`, writing a fabricated commit status for org A's commit [2](#0-1) , [6](#0-5) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

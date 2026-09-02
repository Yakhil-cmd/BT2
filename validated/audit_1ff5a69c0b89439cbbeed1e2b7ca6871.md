Confirmed root-cause split: `WebhooksController#verify_signature` selects the HMAC secret using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) — [1](#0-0) [2](#0-1) . But every event handler resolves the target `Repository`/`Stack` using a *different* field, `payload.dig('repository', 'full_name')`, via `Handler#stacks` / `Handler#repository_name` [3](#0-2) , and `Repository.from_github_repo_name` splits that string on `/` to get owner/name [4](#0-3) .

### Title
Webhook signature verified against `repository.owner.login`, but stack lookup keyed on unrelated `repository.full_name` field — cross-tenant webhook forgery in multi-org deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization Shipit deployments (documented in `docs/setup.md` "Using Multiple Github Applications" and exercised by `test/dummy/config/secrets_double_github_app.yml`), each GitHub organization has its own `webhook_secret` [5](#0-4) . `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC against solely by reading `repository.owner.login` out of the (as-yet-unverified) JSON body [6](#0-5) . Once the signature check passes, the handler dispatch (`PushHandler`, etc.) resolves the actual `Stack`/`Repository` to act on using the independent `repository.full_name` field [3](#0-2) . Nothing ties `owner.login` to `full_name` being consistent — a signature that is valid for organization A's webhook secret authenticates a payload whose `full_name` can reference a repository belonging to organization B.

### Finding Description
The binding that should hold is: `organization whose secret validated the signature == organization owning the repository the handler acts on`. Concretely:

- Verification side: `github_app = Shipit.github(organization: repository_owner)`, where `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) .
- Action side: `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` splits `full_name` on `/` into `repo_owner`/`repo_name` and looks up the `Repository` record directly, with no cross-check against `repository.owner.login` [4](#0-3) , and `Handler#stacks` uses that repository's stacks to run `sync_github` [7](#0-6) , `PushHandler#process` [8](#0-7) .

An attacker who controls a GitHub App/webhook installed on their own organization ("OrgAttacker", with a Shipit-known `webhook_secret`) can, from that app's context, deliver a webhook payload to Shipit's `/webhooks` endpoint (or via any relay they control, e.g., a repository they own with a custom webhook configured to fire to Shipit) where they fully control the JSON body content while only the HMAC is bound to the org config lookup key. Because `repository.owner.login` (used to pick the secret) and `repository.full_name` (used to pick the acted-upon repo) are two independently attacker-writable JSON fields in the same request body, an attacker can set `repository.owner.login = "OrgAttacker"` (so the correct/known secret is used and the signature check passes) while setting `repository.full_name = "OrgVictim/private-repo"` (so the handler resolves and acts on a stack belonging to a completely different, victim organization never installed by the attacker).

Before the attacker's crafted request: `organization authenticated (OrgAttacker) == organization whose repo is acted upon (OrgAttacker)` — binding holds.
After: `organization authenticated (OrgAttacker) != organization whose repo is acted upon (OrgVictim)` — binding is broken, since the webhook signature covers only the byte-for-byte payload, not any semantic invariant tying `owner.login` to `full_name`.

### Impact Explanation
Once mis-scoped, `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on stacks belonging to the victim organization's repository [8](#0-7) , which can trigger unauthorized re-sync/deploy-eligible state changes for a repository/stack the attacker does not control, using only their own (unrelated) org's webhook credentials. This crosses a repository-write / cross-tenant trust boundary between organizations that should be strictly isolated by the multi-app configuration, matching "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
This requires the deployment to use the multi-org GitHub App configuration schema (`github: <org>: ...`) as documented, and requires the attacker to control (or have compromised) a legitimately configured organization's webhook delivery in order to obtain a validly signed request — an unprivileged attacker cannot forge the HMAC for an org they don't control. This significantly limits realistic exploitation to attacker-operated orgs within a shared, multi-tenant Shipit instance, i.e., "unprivileged" relative to the victim org but requiring at minimum control of a co-tenant org's app/webhook secret, which is a meaningfully weaker prerequisite than compromising the victim org itself.

### Recommendation
After signature verification, re-derive `repository_owner` from the same field the handler will use (`repository.full_name`'s owner segment) or explicitly assert `payload.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first` before dispatching to handlers; alternatively, pass the verified `repository_owner` into `Handler.call` and have `Handler#stacks` reject any repository whose owner does not match.

### Proof of Concept
1. Shipit configured with multi-org github secrets, e.g. as in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne`, `OrgTwo`, each with its own `webhook_secret`) [9](#0-8) .
2. Attacker controls `OrgOne`'s GitHub App/webhook (knows/can trigger delivery signed with `OrgOne`'s `webhook_secret`).
3. Attacker crafts (or relays) a `push` event body: `{"ref": "refs/heads/main", "after": "<sha>", "repository": {"owner": {"login": "OrgOne"}, "full_name": "OrgTwo/victim-repo"}}`, computes/obtains the `X-Hub-Signature` using `OrgOne`'s secret.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgOne")` and the signature check passes [1](#0-0) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` resolves `Repository.from_github_repo_name("OrgTwo/victim-repo")` [3](#0-2) , and `sync_github` is triggered on `OrgTwo`'s stack despite the request only ever being signed by `OrgOne`'s secret.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

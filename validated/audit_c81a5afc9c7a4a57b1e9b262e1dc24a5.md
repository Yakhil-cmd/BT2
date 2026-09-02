### Title
Webhook signature verification authenticates a different organization than the one whose repository data is written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` determines *which organization's* webhook secret to use for HMAC verification from `params.dig('repository', 'owner', 'login')`, while the `create` action that actually dispatches the event to handlers re-derives the payload from `JSON.parse(request.raw_post)`. Because Rails merges query-string parameters over parsed JSON body parameters for identical top-level keys, an attacker can make `repository_owner` resolve to an organization whose webhook secret they know (e.g., their own onboarded org), while the raw body signed and dispatched to handlers describes a completely different (victim) repository/organization.

### Finding Description
The signature check is: [1](#0-0) 

`repository_owner` is computed from `params`, Rails' merged parameter hash (body JSON parsed by the JSON parameter parser, merged with query-string parameters — with query-string values taking precedence for identical keys): [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `GitHubApp` (and its `webhook_secret`) keyed strictly by that organization name: [3](#0-2) 

The actual event body used for dispatch, however, is independently re-parsed straight from the raw POST body, with no ties to `repository_owner`: [4](#0-3) 

Each handler (e.g. `PushHandler`, `MembershipHandler`) then acts purely on that raw-body payload: [5](#0-4) [6](#0-5) 

The equality the app implicitly relies on is: `organization used to select webhook_secret for HMAC verification == organization/repository whose data is written by the dispatched handler`. This equality does not hold, because:
- `verify_signature`'s `repository_owner` is sourced from Rails' merged `params`, where query-string keys override same-named body keys during Rails' parameter merge.
- The `create` action's dispatched payload is sourced independently from `request.raw_post`, unaffected by query string.
- The HMAC itself is computed over the entire `request.raw_post` (correct), but the *secret selected* to validate that HMAC is not bound to the same organization data that is subsequently written.

An attacker who legitimately onboards their own organization/repository into this multi-tenant Shipit instance (and therefore knows the `webhook_secret` they configured for their own org) can:
1. Craft a `push`/`status`/`membership` JSON body describing a victim organization/repository/team that they do not control.
2. Sign that exact raw body with their own known `webhook_secret` (HMAC-SHA1, matching `verify_webhook_signature`'s `algorithm`/`OpenSSL::HMAC.hexdigest` check).
3. Append a query string such as `?repository[owner][login]=attacker-org` so `repository_owner` resolves to their own org during `verify_signature`, passing the HMAC check with their own secret.
4. The `create` action re-parses the raw body describing the victim, and dispatches it unmodified to registered handlers for `Repository.from_github_repo_name(repository_name)` derived purely from the signed victim payload.

### Impact Explanation
This breaks the authentication boundary between GitHub organizations onboarded to the same Shipit instance: possession of one organization's legitimate webhook secret is sufficient to forge webhook events attributed to any other organization/repository tracked by the instance. Concretely reachable handlers include:
- `MembershipHandler`, which creates/deletes `Team` and `Membership` records and can add an arbitrary GitHub login to a `Team`: [7](#0-6) . Team membership feeds into `Shipit.github_teams` OAuth authorization (`Shipit.github_teams` maps `oauth_teams` to `Team` records used for access control), so forging `membership` events lets an attacker escalate/self-assign into privileged teams for a victim organization they don't administer — matching the High-severity criterion "escalation into `Shipit.github_teams` authorization".
- `PushHandler`, which triggers `stack.sync_github` for the victim's tracked stacks based purely on the forged, attacker-signed body: [5](#0-4) , potentially influencing deploy eligibility state for a stack the attacker has no legitimate write access to.

The root cause is entirely within engine code (`WebhooksController`, `Shipit.github`, `Webhooks::Handlers`), requires no session, no `ApiClient` token, no GitHub App private key, and no repository write access to the victim — only a legitimately-configured webhook secret for *any* organization on the same multi-tenant instance.

### Likelihood Explanation
Exploitability requires: (a) the Shipit instance is multi-tenant (multiple orgs each configuring their own `webhook_secret` via `secrets.github`, per `github_app_config`), and (b) the attacker controls onboarding of at least one such organization, which is the normal, documented workflow for adding a repository to Shipit (an org admin configures the GitHub App/webhook integration themselves and therefore knows their own secret). Combined with the well-known Rails behavior that query-string parameters override same-named JSON body parameters in the merged `params` hash, this is straightforward to exploit with a single crafted HTTP request and no special access.

### Recommendation
Bind the signature-verification organization strictly to the raw JSON body, not to Rails' merged `params`. Concretely:
- In `WebhooksController`, parse `request.raw_post` once (e.g., `@parsed_body ||= JSON.parse(request.raw_post)`) and derive `repository_owner` exclusively from that parsed body, never from `params`/query string.
- After computing `repository_owner` and its `GitHubApp`, verify that the same value is used consistently by both `verify_signature` and `create` for the same request, and reject any request where query-string parameters attempt to inject a `repository` or `organization` key at all.
- Consider additionally validating that `repository_name`/`organization` extracted in each `Handler` matches the organization used to validate the signature, as defense in depth.

### Proof of Concept
```
POST /github/webhooks?repository[owner][login]=attacker-org HTTP/1.1
Host: shipit.example.com
Content-Type: application/json
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1 of raw body below, keyed with attacker-org's known webhook_secret>

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "victim-org" } }
}
```
1. `verify_signature` computes `repository_owner` from Rails' merged `params`, where the query string `repository[owner][login]=attacker-org` overrides the body's `repository.owner.login`, yielding `"attacker-org"`.
2. `Shipit.github(organization: "attacker-org")` returns the attacker's own `GitHubApp`, whose `webhook_secret` the attacker used to sign the raw body — verification succeeds.
3. `create` re-parses `request.raw_post` (unaffected by the query string), obtaining `repository.full_name == "victim-org/victim-repo"`, and dispatches `PushHandler.call` for that payload, causing `stack.sync_github` to run against the victim's stack under a forged signature the attacker never actually knew.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

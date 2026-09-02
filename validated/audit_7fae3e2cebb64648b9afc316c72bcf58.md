## Finding: Webhook signature verification is bound to `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field

### Title
Cross-organization forged webhook events due to `repository_owner` (signature scope) vs `repository.full_name` (write scope) mismatch - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/HMAC secret used to authenticate an inbound webhook using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` (fallback `organization.login`). [1](#0-0) [2](#0-1)  Every downstream handler, however, resolves the repository/stack to actually mutate using a completely different field of the same JSON body: `payload.dig('repository', 'full_name')`. [3](#0-2)  These two fields are never checked for consistency against each other, mirroring the reported analog: the value that is authenticated (`agentBalance`/here, the organization whose secret validated the request) is not the value that is acted upon (`record.assets`/here, `repository.full_name`, which selects the `Stack`/`Repository` that gets written to).

### Finding Description
`Shipit.github(organization:)` looks up per-organization configuration (app id, private key, and, crucially, `webhook_secret`) in a multi-org deployment — a configuration mode that is explicitly documented and shipped as the recommended pattern for multi-tenant installs. [4](#0-3) [5](#0-4) 

`GitHubApp#verify_webhook_signature` explicitly treats a missing/blank `webhook_secret` as automatic success:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [6](#0-5) 

This "no secret configured ⇒ verification passes" behavior is not treated as a hard error anywhere; the example configuration files literally ship with `webhook_secret: # nil` as a valid, blank value. [7](#0-6) [8](#0-7) 

Given a multi-org install where organization `OrgA` (unrelated, low-value, or throwaway) is registered without a `webhook_secret`, and organization `OrgB` hosts a security-sensitive, tracked stack, an unauthenticated party can `POST /webhooks` with:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/critical-repo" },
  ...
}
```
`verify_signature` computes `repository_owner == "OrgA"`, looks up `Shipit.github(organization: "OrgA")`, and since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally regardless of the (even absent) `X-Hub-Signature` header. [1](#0-0) 

The request then proceeds to `create`, which dispatches to handlers keyed only by the `X-Github-Event` header, passing the full attacker-controlled JSON body. [9](#0-8)  Handlers resolve the target `Stack`/`Repository` purely from `repository.full_name` — the field never checked against, or covered by, the organization used for signature scoping:
- `Handler#repository_name`/`#stacks` [3](#0-2) 
- `PullRequest::ClosedHandler#repository` / `#review_stack.archive!` [10](#0-9) 
- `PullRequest::ReopenedHandler#repository` / `stack.unarchive!` [11](#0-10) 
- `PushHandler#process` (`stacks.not_archived.where(branch:).each { stack.sync_github(...) }`) [12](#0-11) 

Because `full_name` can name **any** repository tracked by the Shipit instance — including ones belonging to a completely different, properly-secured organization — the attacker can trigger real state changes (archiving/unarchiving review stacks, forcing GitHub re-sync) on stacks they were never authenticated for, purely by piggybacking on an unrelated organization's lack of a webhook secret.

### Impact Explanation
This is a cross-repository/cross-organization write performed by an unauthenticated caller: the party authenticated (trivially, via the secret-less `OrgA`) is not the organization whose repository is written to (`OrgB`). This satisfies the "cross-repository writes" / "an organization that authenticated versus the repository that is written" analog category explicitly called out in scope. An attacker can archive or unarchive arbitrary tracked review stacks, and force `GithubSyncJob`-equivalent resyncs on arbitrary stacks, with zero credentials — no session, no `ApiClient` token, no GitHub App key.

### Likelihood Explanation
High in any multi-organization deployment (the documented/shipped configuration mode) where at least one onboarded organization has not set a `webhook_secret` — a state that is not flagged, warned against, or rejected anywhere in the codebase, and is shown as the default/example value. The endpoint is public (`WebhooksController` skips CSRF and has no `Shipit::Authentication`), so no privileged access is required to reach it.

### Recommendation
- Require `webhook_secret` to be present for every configured organization; refuse to boot, or refuse all webhooks for an org, if it is blank, instead of silently returning `true` from `verify_webhook_signature`.
- Additionally, cross-check that the repository owner asserted for signature verification (`repository_owner`) matches the owner encoded in `repository.full_name` used by the handlers, so a valid signature from one organization can never be used to mutate resources scoped to another.

### Proof of Concept
1. Deploy Shipit with a multi-org `github:` config (per `docs/setup.md` "Using Multiple Github Applications") where `OrgA.webhook_secret` is unset and `OrgB` (target) hosts a tracked, secured stack. [5](#0-4) 
2. Send, without any authentication or valid `X-Hub-Signature`:
```
POST /webhooks
X-Github-Event: pull_request
{
  "action": "closed",
  "number": 1,
  "pull_request": { ... "head": {"sha":"...","ref":"..."}, "user": {"login":"attacker"} },
  "repository": { "owner": {"login": "OrgA"}, "full_name": "OrgB/critical-repo" },
  "sender": {"login": "attacker"}
}
```
3. `verify_signature` resolves `repository_owner = "OrgA"`, finds no `webhook_secret` for `OrgA`, and `verify_webhook_signature` returns `true` unconditionally. [6](#0-5) 
4. `PullRequest::ClosedHandler` resolves the repository via `params.repository.full_name == "OrgB/critical-repo"` and calls `review_stack.archive!`, mutating a stack belonging to `OrgB` despite the request never being authenticated for `OrgB`. [10](#0-9) 

Note: I was not able to fully verify the `MembershipHandler` implementation within the tool budget (only its test names were seen), so I did not include a speculative escalation-into-`Shipit.github_teams` chain via forged `membership` events — that would need direct code review of `app/models/shipit/webhooks/handlers/membership_handler.rb` to confirm whether it fabricates `Team`/membership records from payload data in a way that affects `User#authorized?`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** config/secrets.development.shopify.yml (L5-14)
```yaml
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

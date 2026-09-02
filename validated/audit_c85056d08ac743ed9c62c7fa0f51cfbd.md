### Title
Cross-organization signature confusion allows unauthorized stack sync/deploy trigger via webhook payload `repository.owner.login` vs `repository.full_name` mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a webhook against based on `repository.owner.login` (or `organization.login`), but the downstream event handlers select which `Repository`/`Stack` to act on based on the independent `repository.full_name` field from the very same, attacker-controlled JSON body. In a multi-organization Shipit deployment (the documented "Using Multiple GitHub Applications" configuration), an attacker who legitimately controls one configured GitHub organization/app can forge a webhook whose `owner.login` matches their own org (so it passes signature verification with their own known `webhook_secret`) while `full_name` names a repository belonging to a different, victim organization also configured on the same Shipit instance.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and uses it purely to pick the `GitHubApp`/secret for HMAC verification:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 

`Shipit.github(organization:)` does a case-insensitive lookup of the per-org config (`github_app_config`) and raises only if the organization key is completely unknown, otherwise it returns that org's own `GitHubApp` with its own `webhook_secret`: [3](#0-2) 

Verification (`verify_webhook_signature`) only checks that the raw body's HMAC matches the secret belonging to `repository_owner` — it says nothing about which repository is referenced elsewhere in that same body: [4](#0-3) 

Once verification passes, `create` dispatches the parsed body to handlers keyed only by event type:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [5](#0-4) 

Handlers resolve the target repository/stacks using a **different** field, `repository.full_name`, with no re-check against the field used for signature routing:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`PushHandler`, for example, then triggers a repository sync directly from that resolved stack scope:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [7](#0-6) 

The equality that should be enforced but is not:
`organization authenticated by HMAC (repository.owner.login/organization.login) == organization of the repository whose stacks are mutated (repository.full_name)`.

Before the attacker's forged request: an org's webhook secret can only cause actions on repositories under that same org, because in a legitimate GitHub-originated webhook `repository.owner.login` and `repository.full_name`'s owner segment always agree.
After: since both fields are attacker-supplied JSON under a single signature computed over the whole raw body, the attacker (who owns a `webhook_secret` for *some* org configured on the instance) can set `owner.login` to their own org for verification purposes while setting `full_name` to `victim-org/victim-repo`, which is exactly the field consumed downstream to select stacks. Same field-mismatch pattern applies to `pull_request/*` handlers and other handlers that also key off `repository.full_name` independent of the value used to pick the verification secret.

### Impact Explanation
If exploited on a multi-org Shipit instance, this allows an attacker who is a legitimate operator of one configured GitHub organization (not privileged with respect to the victim org) to force `Stack#sync_github` calls (and potentially other handler-triggered state changes, e.g. review-stack creation/archival) against stacks belonging to a completely different, victim organization's repository — i.e., cross-repository/cross-organization state mutation triggered from an unauthorized origin. This matches the "cross-repository writes / unauthorized deploy" Critical impact category, since `sync_github` can drive subsequent continuous-deployment behavior on the victim's stack using an attacker-chosen `expected_head_sha`.

### Likelihood Explanation
Requires a Shipit instance configured with multiple GitHub organizations (documented, supported feature) where the attacker legitimately controls one of them (has that org's `webhook_secret`, e.g., as an app installer/admin of their own org) but not the victim org. No secret guessing, no GitHub credential theft, and no privileged Shipit account is needed — only crafting a raw webhook POST with mismatched `owner.login` vs `full_name` fields, signed with the attacker's own legitimate secret.

### Recommendation
Ensure the field used to select the verification secret and the field(s) used to resolve the target repository/stack refer to the same value, e.g.:
- Derive `repository_owner` strictly from `repository.full_name`'s owner segment (split on `/`) rather than the separate `repository.owner.login`/`organization.login` fields, or
- After verification, explicitly check that `repository.full_name.split('/').first` (case-insensitively) equals the organization whose secret verified the signature, and reject (422) on mismatch, for every handler path that resolves a repository from the payload independent of `repository_owner`.

### Proof of Concept
Assume a Shipit instance configured with two orgs: `attacker-org` (attacker is the legitimate app owner, knows its `webhook_secret`) and `victim-org` (has a stack tracking `victim-org/victim-repo`).

1. Attacker builds a push-event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>` since they legitimately hold that secret.
3. POST to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC check passes because the attacker used their own real secret over the exact bytes sent. [2](#0-1) 
5. `create` dispatches to `PushHandler`, which resolves `stacks` via `repository.full_name = "victim-org/victim-repo"`, entirely bypassing the fact that verification was performed for `attacker-org`, and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack. [7](#0-6)

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

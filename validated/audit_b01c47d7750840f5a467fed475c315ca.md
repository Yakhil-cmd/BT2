### Title
Signature verification keyed off an unverified `repository.owner.login` field allows cross-organization webhook forgery when multiple GitHub organizations are configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the request against using an attacker-controlled field of the *unverified* JSON body (`repository.owner.login`), while the webhook handlers (e.g. `PushHandler`) later resolve the actual `Stack`/`Repository` to mutate using a *different* field of the same unverified body (`repository.full_name`). Because these two fields are never checked for consistency, and because Shipit explicitly supports multiple GitHub organizations where some may have no `webhook_secret` configured (verification then trivially passes), an attacker can forge a payload that is "verified" against an unprotected organization but whose `repository.full_name` targets a stack belonging to a different, protected organization.

### Finding Description
The webhook flow is:
1. `before_action :verify_signature` computes `repository_owner` from the raw JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) .
2. It looks up the `GitHubApp` for that organization and calls `verify_webhook_signature` on it [2](#0-1) .
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no `webhook_secret` configured: `return true unless webhook_secret` [3](#0-2) .
4. If verification passes, `create` dispatches the *entire unverified body* to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
5. Handlers such as `PushHandler` resolve the target stack using `repository.full_name`, a completely separate field of the same body: `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` [5](#0-4) , then triggers `stack.sync_github(expected_head_sha: params.after)` [6](#0-5) .

Shipit natively supports multiple GitHub organizations per instance, keyed by name, each with its own independent `webhook_secret` — confirmed by `Shipit.github(organization:)` / `github_app_config` [7](#0-6)  and by the test fixture defining two orgs where the second (`OrgTwo`) has `webhook_secret: # nil` [8](#0-7) .

The equality that should hold is: *the organization whose secret authenticated this request* == *the organization/repository whose state the request is permitted to mutate*. Because the controller derives the verification key from `repository.owner.login` and the handler derives the mutation target from `repository.full_name` — two independently attacker-suppliable fields inside the same unsigned-or-weakly-signed body — this binding is broken. An attacker who knows (or guesses) that any organization configured on the instance has no `webhook_secret` set can submit a raw POST with `repository.owner.login` set to that unprotected org (making `verify_webhook_signature` return `true` with no real signature needed) while setting `repository.full_name` to `protected-org/protected-repo`, a stack that belongs to an org that *does* have a secret. The request sails through `verify_signature` and is processed by `PushHandler`, which will trigger `stack.sync_github` (and other handlers can produce further side effects such as team/membership changes) against the protected stack — with **no valid signature at all**.

### Impact Explanation
This is an authentication-bypass class issue: an unauthenticated network attacker can trigger authenticated-organization-only webhook side effects (e.g., forcing GitHub sync / deploy triggers on a stack, membership/team churn from `membership` handler) against a protected repository, by exploiting a Shipit instance's less-protected (no-secret) organization entry as a "confused deputy" to bypass verification for a different, protected repository's stack. This crosses the authentication boundary the signature check is meant to enforce and can cause unauthorized stack state changes / effectively unauthorized deploy triggering, matching the "High: escalation into unauthenticated read/write of stack state" and "unauthorized deploy" impact categories.

### Likelihood Explanation
Exploitability requires the specific operator configuration of at least two organizations on one Shipit instance where one lacks a `webhook_secret` (a state the codebase itself documents/tests as valid, see `test/dummy/config/secrets_double_github_app.yml`). Given that condition, the attack requires no credentials, tokens, or GitHub access — only knowledge that such an org exists and its name (which is easily discoverable e.g. through the app's own UI/API since organization/stack names are not secret). This makes exploitation straightforward once the precondition holds, but the precondition itself (mixed protected/unprotected org configuration) is operator-dependent.

### Recommendation
Do not use an attacker-controlled field of the unverified payload to select the signing key used for verification independent of the field used for authorization. Concretely:
- Verify the signature using every organization key configured (or all keys that could plausibly apply) rather than trusting `repository.owner.login` to select the single verification key, or
- After successful signature verification, cross-check that `repository.owner.login` and `repository.full_name`'s owner segment are consistent with the organization whose key actually verified the signature, rejecting mismatches, and
- Treat organizations with an unset/blank `webhook_secret` as unable to authenticate requests for any repository outside their own explicitly configured repo list, rather than allowing `verify_webhook_signature` to return `true` unconditionally for that org and then letting a differently-named repository be acted upon.

### Proof of Concept
Preconditions: Shipit instance configured with two GitHub organizations, `open-org` (no `webhook_secret`) and `secure-org` (has `webhook_secret`), and `secure-org/secure-repo` is a tracked Stack.

1. Attacker sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "open-org" },
    "full_name": "secure-org/secure-repo"
  }
}
```
2. `verify_signature` computes `repository_owner = "open-org"`, calls `Shipit.github(organization: "open-org").verify_webhook_signature(...)`, which returns `true` immediately because `open-org` has no `webhook_secret` [9](#0-8) .
3. Request passes through to `create`, `PushHandler` is invoked with the full payload, resolves `Repository.from_github_repo_name("secure-org/secure-repo")` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the protected stack [6](#0-5)  — despite never presenting a valid signature for `secure-org`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

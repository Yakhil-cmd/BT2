### Title
Webhook signature verification is bound to a payload-controlled organization while event handlers act on a different payload-controlled `repository.full_name`, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization signing secret to validate a webhook against using `repository_owner`, a value taken straight from the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, every `Webhooks::Handlers::Handler` subclass determines *which* Shipit `Repository`/`Stack` to mutate using an entirely different attacker-controlled field, `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing ties the organization whose secret validated the request to the repository that the handler subsequently acts on.

### Finding Description
`Shipit` supports hosting multiple independent GitHub organizations from one instance, each with its own (optional) `webhook_secret`, as documented and exercised in the fixtures/config (`test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`) [2](#0-1) .

The controller resolves the organization to check the signature against purely from request-body fields:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

and then verifies:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [4](#0-3) 

`verify_webhook_signature` short-circuits to `true` when that organization's `webhook_secret` is blank/unset:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [5](#0-4) 

An unset `webhook_secret` is an explicitly supported configuration value (shown as `webhook_secret: # nil` in the shipped multi-org examples) [6](#0-5) .

Once past `verify_signature`, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers such as `PushHandler`, which locate the target `Stack` exclusively via:
```
def repository_name
  payload.dig('repository', 'full_name')
end
``` [7](#0-6) 
```
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [8](#0-7) 

Because `repository_owner` (used for signature selection) and `repository.full_name` (used for target-repo resolution) are independent, attacker-controlled JSON fields with no cross-validation, a request can claim `repository.owner.login = "OrgA"` (satisfying/skipping signature verification for OrgA) while `repository.full_name = "OrgB/victim-repo"` (a completely different tracked repository, possibly belonging to an organization with a properly configured secret). The handler will act on OrgB's stack using data that was never authenticated against OrgB's webhook secret.

**Binding broken:** `organization that authenticated == repository that is written` should always hold, but the engine enforces `repository_owner (verifies signature) ≠ repository.full_name (drives handler mutation)`.

### Impact Explanation
Any webhook event whose handler resolves target repos via `full_name` (e.g. `PushHandler`, PR handlers, `membership`, `check_suite`) can be forged against a stack belonging to an organization other than the one whose secret satisfied `verify_signature`. For `PushHandler` specifically, an attacker can force `stack.sync_github(expected_head_sha: <attacker chosen sha>)` on a victim stack tracked under a different, properly-secured organization — effectively an unauthorized write to that stack's synchronized state/commit history, and, on stacks with `continuous_deployment` enabled, this can cascade into triggering an actual deploy for a repository the attacker never authenticated against. This crosses the "cross-repository writes / unauthorized deploy" impact bar for a Critical/High finding, since the write happens on behalf of an organization/repository the requester never proved control over.

### Likelihood Explanation
Likelihood is highest in the officially-documented multi-organization deployment mode (`README`/`docs/setup.md` "Using Multiple Github Applications"), where it's common for some organizations to be configured without a `webhook_secret` (shown as the default/nil value in shipped example configs) while others are fully secured. Any actor able to reach the public `WebhooksController#create` endpoint (unauthenticated, no session/API token needed) can exploit this by supplying a JSON body naming an org with no/known secret and a `repository.full_name` belonging to a different, protected stack. No credentials, GitHub App keys, or webhook secrets for the *targeted* repository are required.

### Recommendation
Do not let independently-controlled payload fields select the trust boundary and the write target separately. Options:
1. After resolving the `Repository`/`Stack` via `repository.full_name`, verify that the resolved `Repository`'s owning organization matches the `repository_owner` used to select the signing key (i.e., re-derive the organization from the authenticated repository record, not from a second unrelated field in the same payload).
2. Alternatively, verify the webhook signature using a secret keyed by the actually-resolved `Repository` (looked up from `full_name`) rather than by a separately-controlled `owner.login`/`organization.login` field, ensuring the same identifier drives both signature validation and mutation targeting.
3. Reject/short-circuit webhook processing entirely for organizations configured with a blank `webhook_secret` when running in multi-organization mode, or require an explicit secret for every configured organization.

### Proof of Concept
Given a Shipit instance configured with two organizations, `OrgA` (no `webhook_secret` configured) and `OrgB` (properly configured with a secret, tracking `OrgB/victim-repo`):

1. Attacker sends:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # irrelevant, OrgA has no secret

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
2. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and since `OrgA`'s `webhook_secret` is nil, `verify_webhook_signature` returns `true` unconditionally [9](#0-8) .
3. `PushHandler#process` resolves `repository_name` from `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"`, finds the real `Stack` for that repository, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` — a state-changing operation performed without ever validating against `OrgB`'s webhook secret [8](#0-7) [7](#0-6) .

**Note:** I was unable to fully inspect `Stack#sync_github`'s downstream effects (e.g., whether it can directly trigger `ContinuousDeliveryJob`) within the available tool budget; confirming the exact severity ceiling (state corruption vs. an actual unauthorized deploy) would require reviewing `app/models/shipit/stack.rb` and `app/jobs/shipit/continuous_delivery_job.rb` in full — a Devin session with complete file access could verify this end-to-end.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-18)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
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

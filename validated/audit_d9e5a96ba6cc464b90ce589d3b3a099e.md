### Title
Webhook signature verified against `repository.owner.login`, but payload processing keys off `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In Shipit's multi-organization GitHub App configuration, `WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using `repository_owner` (`repository.owner.login`, falling back to `organization.login`), while the handlers that actually mutate state (`Repository.from_github_repo_name`, driven by `payload.dig('repository', 'full_name')`) key off a *different* field of the same attacker-controlled JSON body. The equality the engine implicitly assumes — "organization whose secret validated the HMAC" == "repository whose Stack is written to" — is never enforced.

### Finding Description
`verify_signature` in [1](#0-0)  computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and uses it to pick a `GitHubApp` config (and thus which `webhook_secret` to verify the HMAC with) via `Shipit.github(organization: repository_owner)`. The signature itself, however, is computed over the entire raw POST body (`request.raw_post`) using generic HMAC-SHA1 verification in [2](#0-1) ; it does not bind the signature to any specific field within the JSON payload beyond "this byte string was signed with organization X's secret."

Downstream, every event handler resolves the target `Repository`/`Stack` using a **different** JSON key — `payload.dig('repository', 'full_name')` — as seen in the shared base class [3](#0-2) , and the `PushHandler` uses that repository's stacks to trigger `stack.sync_github` for arbitrary branches [4](#0-3) .

Because `repository.owner.login` and `repository.full_name` are independent fields inside the same JSON document, and only the *existence* of a valid signature for *some configured organization* is checked (not that the signing organization matches the repository named in the payload), the trust binding "organization authenticated" == "repository written" is broken. Shipit explicitly supports and documents multiple independent GitHub App configurations per Shipit instance, each with its own `webhook_secret`, precisely for multi-tenant use — see `docs/setup.md` "Using Multiple Github Applications" [5](#0-4)  and `Shipit.github_app_config` / `Shipit.github` [6](#0-5) .

### Impact Explanation
An entity that legitimately controls one configured GitHub organization/App on a shared multi-tenant Shipit instance (i.e., possesses a valid `webhook_secret` for *their own* org, obtained the normal way — from the GitHub App they created/administer for their own org, which is a wholly different credential than write access to any *other* tenant's repository) can craft a raw webhook body where `repository.owner.login` names their own organization (so the HMAC validates against their own `webhook_secret`) while `repository.full_name` names a completely different tenant's repository. This body will pass `verify_signature` and then be routed by `Handler#stacks` / `Repository.from_github_repo_name` to the victim tenant's `Stack`, letting the attacker enqueue `sync_github` (push events), fabricate `commit_status`, forge `check_suite` results, or manipulate `pull_request`/`membership` state for a repository/stack they do not own. This is a cross-repository/cross-tenant write achieved purely by crafting a JSON body under a credential scoped to an unrelated organization — matching the Critical "cross-repository writes" impact category.

### Likelihood Explanation
Exploitability requires only that the Shipit deployment be configured with more than one GitHub organization (a documented, supported configuration) and that the attacker administers one of those tenant orgs' GitHub Apps (their own webhook secret) — no access to the victim tenant's repository, GITHUB_TOKEN, or Shipit session is required. Crafting the JSON body with mismatched `owner.login`/`full_name` fields is trivial since these are just independent object literals in the POST body sent directly to Shipit's public webhook endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), cross-check that the organization used to select the `webhook_secret` (`repository.owner.login` / `organization.login`) matches the owner implied by `repository.full_name` (i.e., the org segment of `full_name`) before dispatching to handlers. Reject the webhook (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` and confirm its configured GitHub App/organization is the same one whose secret validated the signature, rather than trusting `full_name` independently of the authenticated organization.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`) [7](#0-6) ; suppose the attacker administers `OrgOne`'s GitHub App and Shipit also hosts `OrgTwo/victim-repo` as a registered stack.
2. Attacker crafts a push payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(OrgOne_webhook_secret, body)>` and POSTs to `/github/webhooks` (or equivalent mounted webhook path) with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgOne")` and validates the HMAC successfully [1](#0-0) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgTwo/victim-repo")` [3](#0-2)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim tenant's stack [4](#0-3) , despite the attacker never having authenticated as or being authorized for `OrgTwo`.

### Citations

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

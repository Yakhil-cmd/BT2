### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but every event handler dispatches on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization webhook secret to check the HMAC signature against using `repository_owner`, but the handlers that subsequently act on the verified payload key their target `Repository`/`Stack` off a completely different payload field, `repository.full_name`. Because Shipit is multi-tenant (one `Shipit.github(organization: ...)` config, and one `webhook_secret`, per organization), an attacker who legitimately controls a webhook secret for *any* one organization configured in this Shipit instance can forge a payload whose `repository.owner.login` matches their own organization (so the signature check passes with their own known secret) while `repository.full_name` names a repository belonging to a different, unrelated organization/stack hosted on the same Shipit instance.

### Finding Description
`verify_signature` computes the authenticating organization purely from attacker-supplied JSON, before the signature has been checked: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). `Shipit.github(organization: repository_owner)` returns the `GithubApp` instance configured for that specific organization (each org has its own `webhook_secret`, as shown in the multi-org secrets layout), and `verify_webhook_signature` HMACs the raw body against *that org's* secret: [3](#0-2) [4](#0-3) 

Once the signature is accepted, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers using the full parsed `params`, not just the confirmed `repository_owner`. Every handler resolves the target repository/stack from `payload.dig('repository', 'full_name')` via the shared base class: [5](#0-4) 

`Repository.from_github_repo_name` splits this string on `/` and looks up `owner`/`name` directly, independent of whatever organization the signature was actually checked against: [6](#0-5) 

The equality this binding is supposed to enforce is: `repository.owner.login (used to pick the verifying webhook secret) == owner(repository.full_name) (used to select the acted-upon Repository/Stack)`. Nothing in `WebhooksController` or `Handler` enforces this equality — an attacker only needs to control the value of one field independently of the other inside a single JSON body they construct and sign themselves.

### Impact Explanation
An attacker who is a legitimate GitHub org admin for *one* organization onboarded to this Shipit instance (and therefore knows/controls that org's `webhook_secret`, which they configured themselves when connecting their org's webhook) can forge signed webhook deliveries whose `repository.owner.login` is their own org, but whose `repository.full_name` points at a stack belonging to an entirely different, unrelated organization/repository hosted on the same Shipit deployment. Depending on the event, this can be abused to:
- Trigger `Push`/`sync_github` for another organization's stack via forged `after` SHAs, forcing spurious sync activity on a repository the attacker doesn't own.
- Forge `status`/`check_suite` events for another organization's commits (`StatusHandler`, `CheckSuiteHandler`), which Shipit uses to gate whether a commit is `deployable?`. Marking foreign commits with a fabricated "success" CI status is a direct path toward an unauthorized deploy, since the deploy gating relies on `Commit#deployable?` derived from these attacker-injected statuses.
- Manipulate `membership`/other organization-scoped events cross-tenant.

This crosses the "unauthorized deploy" bar described as Critical impact, because it lets an attacker who is only authorized for their own organization inject CI signal that Shipit trusts for gating deploys of a repository they do not own or have write access to.

### Likelihood Explanation
This requires Shipit to be configured for more than one GitHub organization (a documented, supported multi-tenant configuration, as shown by `config/secrets.development.shopify.yml` listing multiple orgs each with independent `webhook_secret`s). Any attacker who is able to configure a webhook for their own organization pointing at this shared Shipit instance (a routine, unprivileged action any org owner can perform on their own org) automatically obtains the necessary secret. No Shipit session, `ApiClient` token, or repository write access on the victim repo is required — only knowledge of the attacker's own org's secret, which by construction they possess.

### Recommendation
After verifying the HMAC signature, re-derive the acting repository/stack scope strictly from the organization that was cryptographically authenticated (`repository_owner`), and reject/ignore any event whose `repository.full_name` owner does not match `repository_owner`. Alternatively, only allow a given organization's `GithubApp` webhook secret to authenticate deliveries for repositories owned by that same organization, enforced in `WebhooksController#verify_signature` or in the shared `Handler` base class before dispatching to individual handlers.

### Proof of Concept
1. Attacker legitimately connects `attacker-org` to the shared Shipit instance and knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `push` (or `status`) webhook JSON body with:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - a fabricated `state: "success"` (for the `status` event) referencing a `sha` in `victim-org/victim-repo`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw JSON body.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own secret.
5. `Shipit::Webhooks.for_event('status')` handler resolves the target via `payload.dig('repository','full_name') == "victim-org/victim-repo"`, creating/updating a `Status` for `victim-org/victim-repo`'s commit despite the request never being authenticated by `victim-org`'s webhook secret.

**Note:** I was not able to inspect the full body of `app/models/shipit/webhooks/handlers/status_handler.rb` and `check_suite_handler.rb` due to indexing limits; their exact effect on `deployable?`/deploy gating could not be fully confirmed line-by-line. A Devin session with full repository access would allow verifying the exact downstream deploy-gating logic those handlers trigger.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

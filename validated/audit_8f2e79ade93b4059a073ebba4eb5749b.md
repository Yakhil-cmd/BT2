### Title
Webhook signature verification authenticates the sending GitHub organization but never binds it to the repository the event actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, which is read from the same untrusted, unsigned-at-verification-time JSON body (`params.dig('repository', 'owner', 'login')` or the `organization.login` fallback). [1](#0-0)  Once the signature is accepted, the actual event handlers (`Shipit::Webhooks::Handlers::Handler` and its subclasses) locate the target `Stack`/`Repository`/`Commit` using a completely different field of the same payload: `payload.dig('repository', 'full_name')`. [2](#0-1)  Nothing checks that the org whose secret validated the signature (`repository.owner.login`) actually owns the repository named in `repository.full_name`. This is the same class of bug as the reported issue: a check ("`max_tx_bytes` covers the proposal") that is verified against one thing but silently assumed to cover a different, independently-controlled thing (the combined BeaconBlock+Sidecars size). Here the "thing verified" (org owning `repository.owner.login`) and the "thing acted upon" (repo named in `repository.full_name`) are two independent, attacker-controlled fields.

### Finding Description
`Shipit` supports multiple GitHub organizations in one instance, each with its own `webhook_secret`, `app_id`, and `private_key` configured in secrets (see `config/secrets.development.shopify.yml`). [3](#0-2)  Any org administrator legitimately onboarded onto the shared Shipit instance knows their own org's `webhook_secret` (it is visible/settable in that org's own GitHub App/webhook configuration - a capability outside Shipit and outside any Shipit-issued credential).

The verification flow is:
1. `WebhooksController#verify_signature` computes `repository_owner` from the incoming JSON payload itself, then loads `Shipit.github(organization: repository_owner)` to get that org's `webhook_secret`, and verifies the `X-Hub-Signature` HMAC against it. [1](#0-0) [4](#0-3) 
2. On success, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the handler on the raw, attacker-supplied `params`. [5](#0-4) 
3. Handlers resolve the target repository/stack purely from `payload.dig('repository', 'full_name')` — a value that need not correspond to `repository.owner.login` used in step 1. [2](#0-1) 

Because an attacker fully controls the JSON body they submit (subject only to producing a valid HMAC for whatever `repository.owner.login` they name), they can set `repository.owner.login` to their own controlled org (so the signature check passes with a secret they know) while setting `repository.full_name` to any other repository tracked by the same Shipit instance. Handlers such as the `status` handler write attacker-supplied fields (`state`, `context`, `target_url`, `description`, `created_at`) directly onto a `Commit` belonging to that other repository, as shown by the existing test that creates a `Status` straight from payload fields without any repository-ownership cross-check. [6](#0-5) 

This breaks exactly the class of binding called out in scope: "an organization that authenticated versus the repository that is written."

### Impact Explanation
`ci.require` / `ci.blocking` gates in `shipit.yml` rely on GitHub commit statuses to permit continuous deployment. [7](#0-6)  By forging a `status` webhook — signed with an org they legitimately administer — naming a commit SHA in a repository they do **not** own, an attacker can inject a fabricated "success" status for a required CI context on someone else's tracked stack. If that stack has `continuous_deployment: true` and gates on that context, this forged status can unblock/trigger an unauthorized deploy on a repository outside the attacker's control — a cross-repository write and potentially an unauthorized deploy, matching the engine's Critical impact tier.

### Likelihood Explanation
The only prerequisite is administrative control of any single GitHub organization that has been onboarded into the shared Shipit instance (a routine, low-privilege position relative to other tenants' repositories on the same instance) — no Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required. The only non-trivial requirement is knowing the target victim commit SHA and required CI context name, both of which are public/discoverable via the GitHub UI/API for any repository the attacker can view.

### Recommendation
In `WebhooksController`/`Handler`, after signature verification, require that the organization used to authenticate the request (`repository_owner`) matches the owner segment of `payload.dig('repository', 'full_name')` (and of any other repository-bearing fields the specific handler consumes) before processing the event; reject the event otherwise.

### Proof of Concept
1. Attacker administers `attacker-org`, onboarded in Shipit's `github:` secrets with its own `webhook_secret`.
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim-repo-real-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://example.com",
  "description": "forged",
  "created_at": "...",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature` with `attacker-org`'s `webhook_secret` over the raw body and POSTs it to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner == "attacker-org"`, loads `attacker-org`'s secret, and the signature validates. [8](#0-7) 
5. The `status` handler processes the event using `repository.full_name == "victim-org/victim-repo"`, writing the forged `success` status onto the victim's real commit, satisfying `ci.require`.

### Citations

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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** README.md (L444-480)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
  require:
    - ci/circleci
```

**<code>ci.hide</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to ignore.

For example:
```yml
ci:
  hide:
    - ci/circleci
```

**<code>ci.allow_failures</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to be visible but not to required for deploy.

For example:
```yml
ci:
  allow_failures:
    - ci/circleci
```

**<code>ci.blocking</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to disallow deploys if any of them is missing or failing on any of the commits being deployed.

For example:
```yml
ci:
  blocking:
    - soc/compliance
```
```

### Title
`WebhooksController` selects the HMAC secret from `repository.owner.login`/`organization.login` while `StatusHandler` and other handlers act on `repository.full_name`/`sha` from the same untrusted payload, letting an org that only authenticates its own webhook forge state for a repository it does not own - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to verify against based on `repository.owner.login` (falling back to `organization.login`), both attacker-supplied JSON fields. [1](#0-0) [2](#0-1)  Once that HMAC check passes, event handlers act on a *different* field of the same body - `repository.full_name` for stack/repository lookup, or, worse, a bare `sha` with no repository scoping at all in `StatusHandler`. [3](#0-2) [4](#0-3)  The signature only guarantees that the whole body was signed by *some* organization's secret, not that the organization used to select the secret is the same organization whose repository/commit is actually mutated.

### Finding Description
`Shipit` supports a documented multi-tenant configuration where several independent GitHub organizations each get their own `webhook_secret` in `config/secrets.yml`. [5](#0-4)  For every inbound webhook, `verify_signature` resolves the app config to use for the HMAC check purely from attacker-controlled JSON:

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
``` [6](#0-5) 

The HMAC itself (`GitHubApp#verify_webhook_signature`) is computed over the *entire* raw body using the secret belonging to whichever organization name was extracted above. [7](#0-6)  This proves only "this body was signed with Org X's secret" - it says nothing about whether the repository/commit fields the handler subsequently acts on actually belong to Org X.

Downstream, `Handler#repository_name` (used by push/pull_request handlers) reads a *separate* field, `repository.full_name`, to resolve the target `Repository`/`Stack`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [8](#0-7) 

`StatusHandler` is worse still - it does not consult `repository` at all; it updates **any** commit anywhere in the installation matching an attacker-supplied `sha`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Because `repository_owner` (used for key selection) and `repository.full_name`/`sha` (used for the actual write) are independent, attacker-controlled fields inside the same signed body, an attacker who legitimately controls Org A (and thus knows Org A's own `webhook_secret`, e.g. because they created that GitHub App/org themselves on a shared Shipit instance serving multiple orgs) can craft a payload where `repository.owner.login = "OrgA"` (so the correct/known secret is selected and the HMAC passes) but `sha` (for `status` events) or `repository.full_name` (for `push`/`pull_request` events) references a repository/commit belonging to an unrelated Org B also configured on the same instance. The equality that should hold is:

`organization used to verify the signature == organization whose repository/commit state is mutated`

but the code only enforces "some known secret signed this body," not that equality.

### Impact Explanation
Via `StatusHandler`, an attacker who only controls their own org's webhook secret can inject arbitrary CI/status states (`state: "success"`) for any commit SHA in the entire Shipit installation, including commits belonging to stacks of other, unrelated GitHub organizations tracked by the same Shipit instance. `Commit#deployable?` depends directly on the aggregated status state (`success? && !blocked?`), and `Commit#schedule_continuous_delivery` can trigger `ContinuousDeliveryJob` once a commit becomes "successful." [9](#0-8) [10](#0-9)  This can move a targeted commit in another organization's stack from blocked/pending to deployable and trigger continuous deployment/merge machinery for a repository the attacker does not control - an unauthorized deploy driven purely by a cross-tenant identity-binding confusion, matching the Critical impact bucket ("unauthorized deploy").

### Likelihood Explanation
Exploitability requires only that the attacker be a legitimate administrator of *any* GitHub organization configured on a shared/multi-tenant Shipit instance (a supported, documented configuration), knowledge of that organization's own webhook secret (which they set themselves), and knowledge or guessability of a target commit SHA belonging to another tracked organization's stack (commit SHAs are often public/discoverable via GitHub itself). No Shipit session, `ApiClient` token, `api_clients_secret`, or GitHub App private key is needed. This is a plausible but not trivially universal scenario since it depends on the shared multi-org deployment pattern; likelihood is best characterized as Medium.

### Recommendation
After signature verification succeeds, re-derive and cross-check that the organization that supplied the verified secret matches the organization implied by every repository/commit field the handler subsequently acts on (e.g., verify `repository.full_name.split('/').first == repository_owner` before processing, and scope `StatusHandler`'s `Commit` lookup by the resolved `Repository`/`Stack` rather than a bare global `sha` lookup).

### Proof of Concept
1. Shipit is deployed with the multi-org config schema, tracking both `OrgA/repo-a` (attacker-controlled, attacker knows `webhook_secret_A`) and `OrgB/repo-b` (unrelated, tracked stack, some commit `sha_b` currently pending/blocked CI).
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<sha_b belonging to OrgB/repo-b>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/repo-a" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature using `webhook_secret_A`, since the entire body (including the forged `sha`) was legitimately signed with a secret the attacker knows. [1](#0-0) 
5. `StatusHandler#process` ignores `repository` entirely and updates the status of `Commit.where(sha: "<sha_b>")` - a commit belonging to `OrgB`'s stack - to `success`. [4](#0-3) 
6. If that commit is otherwise the newest undeployed commit and `OrgB`'s stack has `continuous_deployment` enabled, `Commit#schedule_continuous_delivery` fires `ContinuousDeliveryJob`, resulting in an unauthorized deploy of `OrgB`'s stack triggered entirely by `OrgA`'s attacker-controlled webhook secret. [10](#0-9)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

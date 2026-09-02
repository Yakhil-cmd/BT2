### Title
Webhook signature verification authenticates the wrong organization/repository binding, enabling cross-tenant webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using a value read directly from the *unverified* JSON payload (`repository.owner.login` / `organization.login`). Every other part of the pipeline — including the handlers that decide *which repository/stack the payload acts on* — reads a different, independently attacker-controlled field (`repository.full_name`). Because these two fields are never bound together by the signature check, an attacker who knows the `webhook_secret` for any one organization configured on a shared Shipit instance can forge a webhook whose `owner.login` names "their" organization (so the correct, known secret is used to pass HMAC verification) while `full_name` names a completely different, victim organization's repository. The handler then acts on the victim repository using attacker-supplied payload data.

### Finding Description
Shipit supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret`: [1](#0-0) [2](#0-1) 

The webhook signature check picks *which* organization's secret to use for verifying the request body based on a field read straight out of the (still-unverified) JSON body: [3](#0-2) [4](#0-3) 

`verify_webhook_signature` merely checks that the raw body's HMAC matches the secret for that named organization — it does not, and cannot, restrict any other field inside that same signed body: [5](#0-4) 

Once the signature passes, every webhook handler determines the target repository from a *different* field, `repository.full_name`, and looks it up globally (not scoped to the organization that "authenticated"): [6](#0-5) [7](#0-6) 

Since an attacker forging the whole HTTP request controls the entire JSON body before computing its own HMAC, nothing stops them from setting `repository.owner.login` (or `organization.login`) to an organization X whose `webhook_secret` they know, while setting `repository.full_name` to `"Y/target-repo"` for a totally unrelated organization Y also hosted on the same Shipit instance. The signature check only validates "this body was signed with X's secret" — it never validates "and this body only concerns X's repositories." This breaks exactly the trust binding: *organization that authenticated (X) ≠ repository that is written (Y/target-repo)*.

This is a structural analog of the reported bug class: a single conditional/selector (`_tokenAddress == wrappedNativeToken` picking the transfer mode) conflates two things that should be independently verified — here, "which secret authenticated this request" is conflated with "which repository this request is authorized to affect," because both are sourced from attacker-writable JSON without cross-binding.

### Impact Explanation
Any handler acting on push/status/check_suite/pull_request events can be triggered against a victim organization's stacks by an attacker who only needs to know one configured organization's `webhook_secret` on a shared multi-tenant Shipit instance (e.g. an org admin of a lower-trust org). Depending on which handler fires, this can:
- Force `GithubSyncJob`/`RefreshCheckRunsJob` to run against arbitrary stacks (`PushHandler`, `CheckSuiteHandler`), forging commit/CI state used for continuous deployment decisions.
- Forge commit statuses via `StatusHandler` for a victim repository's commit, which can influence deploy-safety checks feeding into automatic/continuous deployment gating.
- Manipulate pull-request-driven review-stack lifecycle (`labeled_handler`, `closed_handler`, `reopened_handler`) for a victim repository's review stacks.

Because commit statuses and CI signals gate Shipit's continuous deployment/merge-queue logic, this can escalate to unauthorized deploy/merge actions against a repository the attacker has no legitimate access to — satisfying the "unauthorized deploy, rollback, or merge" Critical impact criterion, contingent on the specific continuous-deployment configuration of the victim stack (not fully traced in this pass — see Uncertainty below).

### Likelihood Explanation
The exploit requires: (1) a Shipit deployment configured with more than one GitHub organization (explicitly supported and documented, e.g. `config/secrets.development.shopify.yml`), and (2) the attacker knowing the `webhook_secret` of at least one configured organization (plausible for an org admin who set up their own GitHub App installation on a shared instance, without needing any Shipit credentials, `ApiClient` token, or repository write access to the victim org). No interaction with Shipit's own authentication/session system is required — only an HTTP POST to the public `/webhooks` endpoint. This is a realistic multi-tenant deployment scenario.

### Recommendation
Do not let the webhook payload's own fields decide which secret validates it independent of what it claims to act on. Recommended fixes:
1. Bind the repository being acted upon to the same authenticated organization: after selecting `Shipit.github(organization: repository_owner)` and verifying the signature, re-derive/validate that `repository.full_name`'s owner segment matches `repository_owner` (case-insensitively) before dispatching to any handler; reject otherwise.
2. Prefer deriving the verifying organization from a source outside the attacker's control where possible (e.g., match against the `installation.id` in the payload cross-checked against configured `installation_id` for that organization, rather than trusting `repository.owner.login`/`organization.login` directly).
3. Scope the stack/repository lookup in `Shipit::Webhooks::Handlers::Handler#stacks` to repositories belonging to the organization that authenticated the request, rather than a global `Repository.from_github_repo_name` lookup.

### Proof of Concept
Preconditions: Shipit instance configured with two organizations, `org-a` (attacker-controlled, attacker knows `webhook_secret_a`) and `org-b` (victim, hosts a tracked stack `org-b/victim-repo`).

1. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_a, raw_body)>` using the known secret for `org-a`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#repository_owner` returns `"org-a"` (from `repository.owner.login`), so `Shipit.github(organization: "org-a")` is used and `verify_webhook_signature` succeeds because the signature was computed with `org-a`'s real secret. [3](#0-2) 
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves the target stacks via `payload.dig('repository','full_name')` = `"org-b/victim-repo"`, entirely unrelated to `org-a`. [8](#0-7) [6](#0-5) 
6. Shipit acts on `org-b`'s stack (triggers sync/deploy-relevant processing) despite the request only being authenticated as belonging to `org-a`.

**Uncertainty**: I was not able to fully trace, within this pass, the exact downstream path from forged commit-status/check-run webhooks through to an actual unauthorized deploy trigger (e.g., continuous-deployment auto-trigger conditions in `app/jobs/shipit/continuous_delivery_job.rb` and `app/models/shipit/stack.rb`), so the escalation from "cross-org webhook forgery" to a concrete "unauthorized deploy" depends on the victim stack's specific `continuous_deployment`/merge-queue configuration, which I could not fully confirm as reachable end-to-end in the time available.

### Citations

**File:** config/secrets.development.shopify.yml (L5-18)
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
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

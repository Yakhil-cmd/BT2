### Title
Webhook signature scoped to attacker's own organization is reused to forge cross-organization commit statuses that trigger deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` verifies the HMAC signature of an inbound GitHub webhook against the `webhook_secret` of the organization derived from the payload itself (`repository.owner.login`, falling back to `organization.login`), not against the organization that actually owns the target repository being acted upon. [1](#0-0)  Downstream, the `status` event handler (`StatusHandler`) does not check the repository at all — it simply looks up any `Commit` by `sha` across the entire Shipit installation and writes a new `Status` for it. [2](#0-1)  Because a multi-tenant Shipit instance can be configured with independent `webhook_secret`s per GitHub organization, [3](#0-2)  an attacker who legitimately controls one configured organization's GitHub App/webhook secret can forge a signature that Shipit will accept, then supply a `sha` belonging to a commit in a completely different organization's stack, causing Shipit to record an attacker-chosen commit status (e.g., `success`) for that foreign commit. This directly feeds `Commit#schedule_continuous_delivery` and `Stack#trigger_continuous_delivery`, which trigger a real deploy once the required status is "success". [4](#0-3) [5](#0-4) 

### Finding Description
The binding that should hold is: **organization whose webhook signature was verified == organization owning the repository/stack that is mutated**. This binding is broken.

1. `verify_signature` selects the GitHub App config (and thus the secret used for the HMAC check) using `repository_owner`, read straight out of the untrusted JSON body:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 
This field is entirely attacker-controlled content inside the same signed raw body — HMAC only guarantees the *bytes* are unmodified relative to whichever secret was used, it says nothing about whether the *values inside* those bytes are internally consistent. Since the attacker computes the signature themselves (using their own legitimately-configured org's secret) they can freely choose every field's value, including `repository.owner.login`, `organization.login`, and (crucially) the `sha` used by the `status` event.

2. `Shipit.github(organization: repository_owner)` in a multi-org deployment resolves to a distinct `GitHubApp` per organization, each with its own `webhook_secret`, via `github_app_config`:
```ruby
def github(organization: github_default_organization)
  ...
  config = github_app_config(organization)
  raise GithubOrganizationUnknown, organization if config.nil?
  ...
end
``` [7](#0-6) 
So the signature check is: "is this HMAC valid for the secret belonging to org X (attacker's own org, as claimed in the payload)?" — a check the attacker trivially passes with their own credentials.

3. The actual handler that processes the `status` event never re-validates that the commit/stack it mutates belongs to organization X:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1)  There is no join to `repository`/`stack`/`organization` here — any commit sha known to Shipit (across every stack/org hosted on the instance) is eligible for a forged status update.

4. Writing a `Status` record cascades into deploy automation: `after_commit :schedule_continuous_delivery` on `Status` calls `Commit#schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` if the commit `deployable?` and the stack has `continuous_deployment?` enabled. [4](#0-3) [5](#0-4)  Existing tests confirm that creating a `success` status on a commit with `continuous_deployment: true` directly enqueues a `Deploy`. [8](#0-7) 

### Impact Explanation
This is an **unauthorized deploy** achieved purely by an attacker who is an authenticated, unprivileged party in Shipit's threat model with respect to the victim org — they only control the legitimate webhook secret for their own (unrelated) organization hosted on the same shared Shipit instance. By forging a `status` webhook keyed to a commit sha in a victim stack and setting `state: success` on a monitored CI context, they can flip `Commit#deployable?` to true and trigger `Stack#trigger_continuous_delivery`, causing Shipit to execute a real deploy task against the victim's infrastructure without ever compromising the victim's GitHub App, webhook secret, or Shipit session/API token. This matches the required Critical impact class of "an unauthorized deploy."

### Likelihood Explanation
The precondition is that the Shipit deployment is configured for multiple organizations (the documented, supported `config/secrets.yml` schema keyed by organization name, exactly as shown in `config/secrets.development.shopify.yml`). [3](#0-2)  In that configuration, any organization's members with access to its GitHub App settings (which is how you'd legitimately get a `webhook_secret` for your own org in this shared instance) can carry out the attack against every other organization/stack on the same instance, without additional access. The `sha` value needed is often knowable/guessable from public repos or leaked via other channels (commit lists, PRs, etc.), and no rate limiting or repository-scoping is enforced on the `status` handler.

### Recommendation
- In `WebhooksController#verify_signature`, do not let the payload dictate which secret is used for verification of an event whose target repository is derived independently; verify against the secret bound to the *actual* repository being written (looked up from Shipit's own `Repository`/`Stack` records), not the attacker-supplied `repository.owner.login`/`organization.login`.
- In `Shipit::Webhooks::Handlers::StatusHandler` (and any other handler that resolves state by `sha` alone), scope the query to commits belonging to a repository whose owning organization matches the organization whose secret validated the signature, e.g. join through `stacks: { repository: { owner: verified_organization } }` before writing anything.
- Consider it a broader principle across all webhook handlers: only mutate rows that are provably associated with the `verified_organization`, never merely the org string embedded in the unauthenticated JSON body used to *select* which secret to check.

### Proof of Concept
Preconditions: Shipit instance configured with `github: { attacker-org: { webhook_secret: S_A, ... }, victim-org: { ... } }` as documented for multi-org deployments.

1. Attacker knows `S_A` (they administer the GitHub App installed on `attacker-org`).
2. Attacker identifies a `sha` belonging to a commit tracked by a stack owned by `victim-org` (e.g., from a public PR/commit list) and confirms that stack has `continuous_deployment: true` with a required CI context, e.g. `ci/travis`.
3. Attacker builds this JSON body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(S_A, body)>` and sends:
```
POST /github_hook  (or wherever WebhooksController is mounted)
X-Github-Event: status
X-Hub-Signature: sha1=<hmac>
```
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (the body's `repository.owner.login`) and validates the HMAC against `S_A` — passes, since the attacker computed it correctly. [9](#0-8) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim's commit (no org scoping), creating a `success` `Status` for it. [2](#0-1) 
7. `Status`'s `after_commit :schedule_continuous_delivery` fires `Commit#schedule_continuous_delivery`, which — if the victim commit is otherwise deployable and the victim stack has continuous deployment enabled — enqueues `ContinuousDeliveryJob`, ultimately calling `Stack#trigger_continuous_delivery` → `trigger_deploy`, executing a deploy on victim infrastructure the attacker never had access to. [5](#0-4) [10](#0-9) 

Note: I could not fully verify from the index whether every production/documented Shipit deployment actually uses the multi-org `secrets.yml` schema in practice (vs. the single-org schema, where `github_default_organization` is `nil` and there is only one secret) — this attack requires the multi-org configuration to create two distinct, independently-controllable secrets. This is a documented and supported configuration (see `config/secrets.development.shopify.yml` and `docs/setup.md`), not a hypothetical one, but I flag this precondition explicitly since I cannot confirm how common multi-org configuration is among real deployments.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

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

**File:** lib/shipit.rb (L170-181)
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
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

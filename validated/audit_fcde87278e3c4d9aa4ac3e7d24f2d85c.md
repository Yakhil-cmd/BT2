This confirms the key attack path. The `StatusHandler` combined with `Stack#continuous_deployment?` gives clear Critical impact: an attacker who forges a `status` webhook with `state: 'success'` for a specific `sha` (and any `context`) causes `Commit#create_status_from_github!` to create a `Status`, which triggers `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` → `trigger_deploy`, i.e. an **unauthorized deploy**, on any stack with `continuous_deployment: true`, as long as the forged commit sha exists in that stack.### Title
Signature verification keyed by `repository.owner.login` does not bind to the `repository.full_name` handlers act on, allowing cross-organization forged status/push events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the HMAC against using `repository_owner`, a field read from the *untrusted* JSON body (`params.dig('repository', 'owner', 'login')`). Every downstream handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, PR handlers), however, resolves the target `Stack`/`Commit` using a *different* body field, `repository.full_name` (`Shipit::Webhooks::Handlers::Handler#repository_name`). Nothing enforces that these two independently-attacker-controlled fields refer to the same repository, so a correctly-signed webhook for organization A can carry a `repository.full_name` pointing at organization B's repo.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
with
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This checks the HMAC (`github_app.verify_webhook_signature`) against the secret configured for the org named in `repository.owner.login`, and the whole raw body is signed - so the signature does authenticate that *some* trusted org's secret was used to sign *this exact body*. The problem is the body itself is entirely attacker-supplied JSON aside from possessing that org's `webhook_secret`; the field used for authentication selection (`repository.owner.login`) is never cross-checked against the field the business logic actually trusts to resolve the target repository:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [3](#0-2) 

`StatusHandler` uses attacker-supplied `sha`/`state`/`context` verbatim to create a `Status` on any `Commit` matching that sha, regardless of stack/org:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Creating a `success` `Status` triggers continuous delivery unconditionally through model callbacks:
```ruby
after_create :enable_ci_on_stack
after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
...
def schedule_continuous_delivery
  commit.schedule_continuous_delivery
end
``` [5](#0-4) 
```ruby
def schedule_continuous_delivery
  return unless deployable? && stack.continuous_deployment? && stack.deployable?
  ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
end
``` [6](#0-5) 
which resolves to `Stack#trigger_continuous_delivery` → `trigger_deploy` [7](#0-6) .

**The broken binding**: "organization authenticated" (`repository.owner.login`, checked against the signing org's `webhook_secret`) ≠ "repository the event is applied to" (`repository.full_name`, used by every handler to look up commits/stacks). The signature only proves the payload was signed by *some* org that has a GitHub App configured in Shipit — it does not prove that org owns the repository the handler will act on.

### Impact Explanation
Any party operating their own GitHub organization/App that Shipit is configured to trust (a routine, low-privilege setup step any org admin can do, and explicitly supported via the multi-org config block in `config/secrets.development.shopify.yml` / `docs/setup.md`) can compute a valid HMAC using their own org's `webhook_secret`, while setting `repository.owner.login` to their own org (to pass signature verification) and `repository.full_name`/`sha` to point at a victim stack/commit they don't own. Sending this to `/webhooks` with `X-Github-Event: status` and `state: success` on a known deployed commit sha of a victim stack with `continuous_deployment: true` triggers an **unauthorized deploy** on that stack — satisfying the Critical impact bar (unauthorized deploy) without ever holding an `ApiClient` token, GitHub write access to the victim repo, or a Shipit session.

### Likelihood Explanation
Requires: (1) Shipit configured with more than one trusted GitHub organization (a documented, supported configuration), (2) the attacker controlling one of those orgs' webhook secret (which they legitimately have as that org's App admin), and (3) knowledge of a valid commit sha for the victim stack (obtainable from the public repo/commit history or the Shipit UI itself, which is often visible with minimal or no auth per `docs/setup.md`'s optional-auth note). No memory/timing side channel or crypto break is needed — only that Shipit's signature check does not bind the signing organization to the body's `repository.full_name`.

### Recommendation
In `WebhooksController#verify_signature`, after establishing which org's secret verified the signature, also derive the repository's owning organization from `repository.full_name` (not `repository.owner.login`) and require it to match `repository_owner` before dispatching to handlers; reject (422) on mismatch. Equivalently, have each `Handler` re-validate that the payload's `repository.full_name` owner matches the organization whose GitHub App secret validated the signature, rather than trusting `repository.full_name` unconditionally.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two orgs: `victim-org` (its GitHub App secret unknown to attacker) and `attacker-org` (App secret known to the attacker, who legitimately administers it).
2. Attacker builds a JSON body:
```json
{
  "action": "status",
  "sha": "<known-deployed-sha-of-victim-stack>",
  "state": "success",
  "context": "ci/attacker",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org webhook_secret, body)>` and POSTs to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC verifies successfully (attacker knows this secret).
5. `Shipit::Webhooks::Handlers::StatusHandler` runs, finds the `Commit` by `sha` in `victim-org/victim-repo`'s stack (unrelated to `attacker-org`), and creates a `success` `Status`.
6. If that victim stack has `continuous_deployment: true`, `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` fires an unauthorized deploy, with no relationship between `attacker-org` and the victim repository ever verified.

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

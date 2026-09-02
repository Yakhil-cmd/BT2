### Title
Webhook signature verification org is unbound from the repository/stack the event actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against based on `repository_owner`, a field read from the *unauthenticated* JSON body (`repository.owner.login` or `organization.login`). [1](#0-0)  Once the signature check passes, every handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, etc.) resolves the actually affected `Stack`/`Repository` from a *different* field of the same unauthenticated body: `payload.dig('repository', 'full_name')`. [2](#0-1)  Nothing binds `repository.owner.login` (the identity whose secret authenticated the request) to `repository.full_name` (the identity that is actually acted upon).

### Finding Description
The binding that should hold is:

`organization whose webhook_secret authenticated the request == organization/repository whose stacks are mutated by the event`

In Shipit, a single instance can be configured with multiple GitHub orgs, each with its own `webhook_secret` (see `config/secrets.development.shopify.yml`, showing `somegithuborg` / `someothergithuborg` each with independent secrets). [3](#0-2)  `GithubApp#verify_webhook_signature` only proves that the HMAC of the raw body matches the secret configured for whichever org name is present in the payload's `repository.owner.login`; it says nothing about which repository the same payload's `repository.full_name` refers to:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

Because the attacker crafts the entire raw body and signs it themselves with a secret they legitimately possess (e.g. as an admin of Org A's GitHub App/webhook config), they can set `repository.owner.login = "OrgA"` (so the correct/known secret is picked for verification) while setting `repository.full_name = "OrgB/some-other-repo"` (a repository belonging to a completely different, unrelated org configured on the same Shipit instance). The signature will verify successfully because it is a valid HMAC over the attacker-authored body under Org A's secret — the verification step never checks that `repository.full_name` starts with `repository.owner.login`.

Every handler then trusts `repository.full_name` alone to select stacks: `Repository.from_github_repo_name(repository_name)&.stacks`. [2](#0-1)  For example `PushHandler` calls `stack.sync_github(expected_head_sha:)` for every non-archived stack matching the branch of Org B's repository, [5](#0-4)  and `StatusHandler`/commit-status ingestion feeds into `Commit#schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` once `stack.continuous_deployment?` and `stack.deployable?` are true. [6](#0-5)  `Status#schedule_continuous_delivery`/`after_commit` hooks the same path when a `success` status is recorded. [7](#0-6)  `Stack#trigger_continuous_delivery`/`trigger_deploy` then build and run a `Deploy` for the targeted stack. [8](#0-7) 

### Impact Explanation
An attacker who controls the webhook secret/configuration for one org onboarded to a shared Shipit instance can forge a `status` (or `push`) event that claims to originate from that org (so signature verification passes) but names a repository belonging to a completely unrelated org/team on the same instance. If that unrelated stack has `continuous_deployment` enabled, this can inject a forged "CI success" status for an arbitrary commit and trigger an **unauthorized deploy** on a stack the attacker has no legitimate access to — matching the Critical-impact criterion "an unauthorized deploy, rollback or merge." It can also drive `sync_github`/`GithubSyncJob` and `MembershipHandler` state changes (team/user creation) against stacks/orgs the requester does not own.

### Likelihood Explanation
Exploitation requires the attacker to already control (or know) the `webhook_secret` for at least one org configured on the shared Shipit instance — a realistic scenario for a multi-tenant deployment where each onboarded team configures its own GitHub App/webhook but shares the Shipit installation with other, mutually-untrusted teams. No `ApiClient` token, session, or GitHub App private key is needed — only knowledge of one org's webhook secret, which is materially weaker than the assumptions the "OUT OF SCOPE" rule excludes (session, `api_clients_secret`, GitHub App private key, repo write access). This is plausible but does depend on the "multiple independent orgs sharing one Shipit instance" deployment pattern being in effect, which is a supported and documented configuration (`config/secrets.development.shopify.yml`).

### Recommendation
Bind the verification identity to the mutation identity: after determining `repository_owner` and selecting the signing `github_app`, also verify that `payload.dig('repository', 'full_name')` (and/or `organization.login`) is owned by/prefixed by that same organization before dispatching to handlers, or resolve the `Repository`/`Stack` using the verified organization rather than trusting the raw `full_name` field alone.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with distinct `webhook_secret`s, both hosting stacks with `continuous_deployment: true`.
2. As someone with access to `orgA`'s webhook secret (e.g. an org admin for `orgA`, not a Shipit admin and with no access to `orgB`), craft a `status` webhook payload:
   ```json
   {
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" },
     "sha": "<commit sha in orgB/target-repo>",
     "state": "success",
     "context": "ci/forged"
   }
   ```
3. Sign the raw body with `orgA`'s `webhook_secret` and send it to `POST /webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner = "orgA"`, fetches `orgA`'s `github_app`, and the HMAC verifies successfully. [9](#0-8) 
5. `StatusHandler` resolves stacks via `repository.full_name = "orgB/target-repo"`, [2](#0-1)  records a `success` status on the targeted commit, which — if `orgB`'s stack has `continuous_deployment` enabled and the commit is otherwise deployable — schedules `ContinuousDeliveryJob` and triggers a deploy the attacker has no authorization over. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/status.rb (L18-45)
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
  end
```

**File:** app/models/shipit/stack.rb (L174-196)
```ruby
    def trigger_deploy(*args, **kwargs)
      if changed?
        # If this is the first deploy since the spec changed it's possible the record will be dirty here, meaning we
        # cant lock. In this one case persist the changes, otherwise log a warning and let the lock raise, so we
        # can debug what's going on here. We don't expect anything other than the deploy spec to dirty the model
        # instance, because of how that field is serialised.
        if changes.keys == ['cached_deploy_spec']
          save!
        else
          Rails.logger.warning("#{changes.keys} field(s) were unexpectedly modified on stack #{id} while deploying")
        end
      end

      run_now = kwargs.delete(:run_now)
      deploy = with_lock do
        deploy = build_deploy(*args, **kwargs)
        deploy.save!
        deploy
      end
      run_now ? deploy.run_now! : deploy.enqueue
      continuous_delivery_resumed!
      deploy
    end
```

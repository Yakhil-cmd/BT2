### Title
Cross-organization commit-status forgery — signature is verified against the organization named in the payload while the write target is the unrelated commit SHA/repository named in the same untrusted payload - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a GitHub webhook by looking up the org's HMAC secret using an attacker-controlled field of the very payload it signs, but the handler that acts on the payload (`StatusHandler`) never re-checks that the authenticated organization actually owns the repository/commit being mutated. This breaks the trust binding "an organization that authenticated versus the repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks which org's `webhook_secret` to verify against straight from the JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `params.dig('repository','owner','login')` — a value inside the same payload whose bytes are being HMAC-verified. Shipit supports (and documents) multi-organization configuration, where each organization onboarded to the same Shipit instance has created its own GitHub App and supplied its own `webhook_secret`: [3](#0-2) 

Because the secret used for verification is selected by an attacker-controlled field, and because HMAC verification only proves "this body was signed with *some* org's secret," any organization onboarded to the same Shipit instance can forge a payload where `repository.owner.login` (or `organization.login`) names *itself* — so the signature check passes with its own known secret — while other payload fields point at a target belonging to a completely different, unrelated repository/organization.

`StatusHandler`, which is dispatched for the `status` event, demonstrates the worst case: it doesn't even use `repository.full_name` to scope its write, it only matches by commit SHA globally across the whole `commits` table: [4](#0-3) 

`Commit#create_status_from_github!` then persists the forged status and re-evaluates deployability/merge scheduling for whichever stack that commit actually belongs to: [5](#0-4) [6](#0-5) 

`Commit#deployable?` and `Commit#schedule_continuous_delivery` directly gate continuous deployment on the (forged) status state: [7](#0-6) [8](#0-7) 

The equality that should hold but does not:
`organization whose secret verified the signature == organization/repository whose state the handler mutates`.

Before the attack: the attacker's org (`Org A`) has its own configured `webhook_secret`. `Org B`'s stack/commit is untouched by Org A's webhook traffic.
After the attack: Org A crafts a `status` webhook with `repository.owner.login = "OrgA"` (so `verify_signature` fetches Org A's own known secret and passes) but `sha` set to a real, undeployed commit SHA belonging to Org B's stack (SHA values are visible on Org B's public GitHub commit history / Shipit UI). The signature is computed by the attacker over the whole forged body using their own known secret, so `verify_webhook_signature` succeeds. `StatusHandler` then updates Org B's commit status, potentially flips a blocking/required check to `success`, and can trigger `schedule_continuous_delivery` for Org B's stack if `continuous_deployment` and `ignore_ci`/blocking checks make it pass — an unauthorized deploy path — or unblock a queued merge (`stack.schedule_merges`) it should never have been able to influence.

### Impact Explanation
This lets one onboarded (but otherwise unprivileged relative to Org B) organization forge CI/status signal for a repository/stack it does not own, on a shared Shipit instance. Depending on stack configuration this can flip a commit from blocked to `deployable?` and trigger `schedule_continuous_delivery`, i.e. an unauthorized deploy of another team's stack, or unblock the automatic merge queue (`stack.schedule_merges`) — both explicitly listed as Critical/High impacts (unauthorized deploy / escalation of authorization boundaries). The write is performed with zero verification that the authenticating org and the targeted commit/repository are the same entity.

### Likelihood Explanation
Requires only that Shipit be configured for more than one GitHub organization (a documented, supported configuration — `docs/setup.md` and `config/secrets.development.shopify.yml`), and that the attacker controls/administers one of those onboarded orgs (i.e., knows its own legitimately-issued `webhook_secret`). No GitHub App private key, no `GITHUB_TOKEN`, no Shipit `ApiClient` token, and no host-repository write access is needed — only the ability to craft and POST an HTTP request with a valid HMAC using a secret the attacker legitimately possesses for their own org. This is a realistic multi-tenant scenario for any Shipit deployment shared across multiple GitHub organizations.

### Recommendation
When processing a webhook, verify that the `repository.full_name` (or `organization.login`) actually named as the write target belongs to the same organization whose secret verified the signature, before dispatching to handlers — e.g., re-derive/compare `repository.owner.login` against the resolved `Repository`/`Stack`'s known owning organization, and reject if they diverge. For `StatusHandler` in particular, scope the `Commit` lookup by `stack`/`repository` (matched to the verified organization) rather than a bare, cross-tenant `sha` lookup.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`), both hosting stacks on the same Shipit instance.
2. As an admin of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret`), craft a `status` event JSON body:
   ```json
   {
     "sha": "<sha of an undeployed, blocking-status commit on an OrgB stack>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "OrgA" } }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s secret, and the signature validates.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the OrgB commit purely by SHA — and calls `create_status_from_github!`, updating OrgB's commit status and potentially triggering `schedule_continuous_delivery`/`schedule_merges` for a stack OrgA never had legitimate access to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

**File:** app/models/shipit/commit.rb (L360-386)
```ruby
    private

    def message_parser
      @message_parser ||= CommitMessage.new(message)
    end

    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

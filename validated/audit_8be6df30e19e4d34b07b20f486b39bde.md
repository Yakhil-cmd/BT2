### Title
Cross-organization commit-status forgery bypasses CI gating - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub organization named in the payload itself, but `StatusHandler#process` applies the status to *any* `Commit` row in the database matching the payload's `sha`, with no check that the commit actually belongs to the organization/repository whose secret validated the request. On a Shipit instance configured with multiple GitHub organizations, this breaks the binding "organization that authenticated the webhook" = "repository whose commit receives the status," letting an operator of one onboarded (less-trusted) org forge a CI status for a completely different org's commit.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from attacker-controlled payload fields and uses it purely to pick which secret to validate the HMAC with: [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple independent GitHub Apps/organizations sharing one instance, each with its own `webhook_secret` known to that org's own maintainers: [3](#0-2) 

Once the signature check passes (proving only "this body was HMAC-signed with orgA's secret"), the event is dispatched to `StatusHandler`, which looks up commits solely by `sha`, with no cross-check against `repository.full_name`/`repository.owner.login` or any relation to the organization that produced a valid signature: [4](#0-3) 

The base `Handler` class does define a `repository_name`/`stacks` helper keyed on `payload.dig('repository', 'full_name')`, but `StatusHandler` does not use it before mutating `Commit` records: [5](#0-4) 

Because `Commit` rows are looked up globally by `sha` regardless of which `Stack`/`Repository` they belong to, an attacker who legitimately administers **orgA** (onboarded to the shared Shipit instance and thus in possession of orgA's real `webhook_secret`) can:
1. Compute a valid HMAC-SHA1 signature over a crafted JSON body using orgA's secret (the same way `Hook`/`DeliverySigner` do it: [6](#0-5) ).
2. Set `repository.owner.login` = `orgA` so `verify_signature` selects and successfully validates against orgA's secret.
3. Set `sha` in the payload to a commit SHA that belongs to a *different* stack/repository (e.g. `orgB/victim-repo`), and `state`/`context` to whatever the victim's `ci.require` context expects, e.g. `success`.
4. POST this to the shared `/github/webhooks` endpoint (the endpoint is not scoped per organization; it dispatches purely on `X-Github-Event`).

`StatusHandler` will happily record a fabricated "success" status on the victim commit: [7](#0-6) 

### Impact Explanation
Commit statuses recorded this way feed Shipit's `ci.require` deploy-gating logic (declared per-stack in `shipit.yml`, see the `status`/`ci` deploy-spec fields: [8](#0-7) ). A forged "success" status for a required CI context can flip a blocked/failing commit into a deployable state for a stack the attacker has no permission on, enabling an **unauthorized deploy** of a commit that never actually passed CI in the victim repository — this satisfies the Critical impact bar ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Low-to-Medium. It requires: (1) the Shipit instance to be configured with multiple GitHub organizations sharing one deployment (an explicitly documented, supported configuration), (2) the attacker to control/administer at least one of the lesser-trusted onboarded organizations and thus legitimately know its `webhook_secret`, and (3) the attacker to know the target commit's SHA and the exact `context` string the victim stack requires (both typically discoverable from the victim's public GitHub repository/`shipit.yml`). None of these require any Shipit session, API token, or GitHub write access to the victim repository — only ordinary control of a different, independently-onboarded org.

### Recommendation
In `StatusHandler` (and any other handler that looks up records purely by `sha`/global identifiers), scope the lookup to the repository named in the signed payload (`payload.dig('repository','full_name')`) and verify it matches the organization that successfully validated the HMAC signature (`repository_owner` in `WebhooksController`) before applying any mutation. Reject events where the signing organization does not own the referenced repository.

### Proof of Concept
1. Deploy Shipit with two orgs configured, e.g. `orgA` and `orgB`, each with distinct `webhook_secret`s (per `docs/setup.md`'s multi-org example).
2. As the operator of `orgA`, compute `sig = HMAC-SHA1(orgA_webhook_secret, body)` for:
```json
{
  "sha": "<victim commit sha in orgB/victim-repo>",
  "state": "success",
  "context": "<context required by orgB/victim-repo's shipit.yml ci.require>",
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/decoy-repo"}
}
```
3. POST to `/github/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<sig>`.
4. `verify_signature` validates against `orgA`'s secret and passes (`app/controllers/shipit/webhooks_controller.rb:24-31`).
5. `StatusHandler#process` finds the `Commit` in `orgB/victim-repo` by `sha` alone and records the forged "success" status (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), regardless that the signature came from `orgA`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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

**File:** app/models/shipit/hook.rb (L54-58)
```ruby
      def signature
        return nil if secret.blank?

        DeliverySigner.new(secret).sign(payload)
      end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L61-69)
```ruby
            'checklist' => review_checklist,
            'monitoring' => review_monitoring,
            'checks' => review_checks
          },
          'plugins' => plugins,
          'status' => {
            'context' => release_status_context,
            'delay' => release_status_delay
          },
```

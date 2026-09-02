### Title
Cross-organization webhook forgery via mismatched signature-authenticated organization and payload-driven target repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an inbound webhook against using one payload field (`repository.owner.login`, falling back to `organization.login`), while every event handler resolves the actual `Repository`/`Stack`/`Commit` that gets mutated using a *different* payload field (`repository.full_name`, or `organization.login` in isolation for membership events). Because nothing cross-checks that these two fields refer to the same GitHub organization, a party who legitimately controls a webhook secret for *one* organization onboarded onto a multi-org Shipit instance can forge a webhook whose signature verifies against their own organization but whose payload body targets a completely different, victim organization's repository.

### Finding Description
`verify_signature` picks the app/secret to check against like this: [1](#0-0) 

using: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization `GithubApp` instance, each with its own independently configured `webhook_secret` (documented multi-org setup where every org has its own `app_id`/`webhook_secret`/`oauth` block). `GithubApp#verify_webhook_signature` only proves that the raw body was signed by *whichever* org's secret was selected — it says nothing about which repository the body actually names: [3](#0-2) 

Once verification passes, `create` blindly hands the entire parsed payload to the registered handlers for the event type: [4](#0-3) 

Every generic handler, however, resolves the target Stack/Repository from a *different* field of the same payload — `repository.full_name` — with no relation back to whichever `repository.owner.login`/`organization.login` was used to pick the verifying secret: [5](#0-4) 

This pattern repeats in the concrete handlers, e.g. push: [6](#0-5) 

and the pull-request label handler, which can archive/unarchive review stacks belonging to any repository it can resolve via `full_name`: [7](#0-6) 

The equality this binding is supposed to enforce is: *organization whose secret authenticated the request == organization that owns the repository being written to*. The code instead enforces two independent, uncorrelated lookups on the same untrusted JSON body, so an attacker who knows the `webhook_secret` for organization `A` (a secret they can legitimately obtain, e.g. by being an admin of their own onboarded GitHub App/org) can set `repository.owner.login = "A"` (satisfies the signature check) while setting `repository.full_name = "victim-org/victim-repo"` (drives which real Stack/Repository gets mutated).

### Impact Explanation
This breaks the trust boundary between organizations that are supposed to be isolated from each other in a multi-tenant Shipit deployment (a configuration explicitly documented and supported by the engine). An attacker who controls only their own onboarded organization can:
- Forge `push` events to trigger `stack.sync_github` on an arbitrary victim stack, causing writes to that stack's cached git state/commits without any authorization from the victim repository's actual GitHub events.
- Forge `status`/`check_suite` events to write bogus `Shipit::Status`/check-run records against a victim's commits — data other parts of Shipit rely on to decide whether commits are ready to deploy.
- Forge `pull_request` label events to archive/unarchive a victim's review stacks.

These are all cross-organization writes into Shipit's model of a repository the attacker does not control, satisfying the "cross-repository writes" Critical-impact criterion. I was not able to fully trace, within this session, whether a forged `status` webhook alone is sufficient to make a `continuous_deployment`-enabled stack auto-deploy an unapproved commit (that would require reading `Stack`'s continuous-delivery gating and `Commit#deployable?`-style logic, which I did not get to inspect before running out of tool calls) — so I present the confirmed impact as unauthorized cross-organization writes to Shipit-managed repository/stack state, and flag the auto-deploy escalation as a plausible but unverified extension.

### Likelihood Explanation
Exploitability only requires: (1) the Shipit instance is configured for more than one GitHub organization (a documented, supported configuration), and (2) the attacker has legitimate admin access to one of those onboarded, lower-trust organizations (enough to read/rotate that org's own `webhook_secret`, a routine GitHub App admin action). No access to the victim's secrets, tokens, or repository is required, matching the unprivileged-attacker threat model in scope.

### Recommendation
Bind the two lookups together: after selecting the `GithubApp`/organization via `repository_owner`, verify that the owner embedded in `repository.full_name` (and, for `organization`-only events, `organization.login`) matches `repository_owner` before dispatching to any handler. Reject (422) the request if they diverge.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per the documented multi-org `secrets.yml` layout).
2. Attacker, an admin of `attacker-org`'s GitHub App, knows `attacker-org`'s `webhook_secret`.
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org_webhook_secret, body)>` and sends `POST /webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner => "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the HMAC verifies successfully (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`).
6. `create` dispatches to `PushHandler`, which resolves the target repository via `payload.dig('repository','full_name') == "victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, `push_handler.rb:12-17`) and calls `stack.sync_github(...)` on the real victim stack — an action the attacker has no authorization to trigger.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

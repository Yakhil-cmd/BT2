### Title
Status webhook handler trusts commit `sha` globally, letting any webhook-authenticated organization forge CI status for commits belonging to a different organization's stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook only against the *organization* derived from the payload's `repository.owner.login` (or `organization.login`) field, selecting that organization's configured `webhook_secret` to validate the HMAC signature. Once that check passes, the `status` event is dispatched to `Shipit::Webhooks::Handlers::StatusHandler`, which never re-checks which repository/organization the event claims to originate from. It looks up commits purely by `sha` across the entire Shipit instance and writes a `CommitStatus` on every match. Any organization with its own legitimately configured Shipit GitHub App (a normal, unprivileged multi-tenant configuration documented in `docs/setup.md`) can therefore sign a `status` webhook as itself, but reference a commit `sha` that actually belongs to a completely different, victim organization's stack, forging a passing CI status for that commit.

### Finding Description
The signature check binds trust to `repository_owner`: [1](#0-0) [2](#0-1) 

This organization identity is used only to pick which `webhook_secret` verifies the raw payload HMAC: [3](#0-2) 

Multi-organization Shipit installations configure a distinct `webhook_secret` per organization, each of which is legitimately known to that organization's own GitHub App owner: [4](#0-3) 

After the signature passes, the event is routed by event name only, with the full, attacker-controlled JSON body handed to the handler: [5](#0-4) [6](#0-5) 

Most handlers scope their side effects to the repository named in the payload via `Handler#repository_name`/`#stacks`: [7](#0-6) 

`StatusHandler`, however, does none of that. It queries `Commit` by `sha` alone, with no repository/organization filter at all, and writes a status onto every matching commit regardless of which stack/repository it belongs to: [8](#0-7) 

The binding that should hold is:
`organization authenticated by verify_signature (repository_owner) == organization/repository whose commit is mutated by StatusHandler`

This equality is never enforced. The only field cryptographically bound by the signature is the raw request body as a whole, verified against the secret chosen from `repository.owner.login`; nothing constrains the `sha` (or any other field) to actually belong to a repository owned by that same organization. An attacker who legitimately owns organization A (with its own Shipit GitHub App and `webhook_secret`) can send a `status` webhook signed with A's secret, set `repository.owner.login` to `A` (so verification succeeds), but set `sha` to a commit hash belonging to victim organization B's stack (commit SHAs are public information visible on GitHub). `StatusHandler` will happily create/update a `CommitStatus` for that commit as if it came from B's CI.

### Impact Explanation
Commit statuses are the signal Shipit uses to gate merges/deploys (CI "required checks"). A forged "success" status on a victim stack's commit can allow that commit to satisfy Shipit's status-based gating and proceed to an unauthorized deploy/merge, without the attacker ever having credentials, GitHub App access, or write access to the victim's actual repository or organization. This crosses an organizational trust boundary purely by exploiting the absence of repository/organization scoping in `StatusHandler#process`, matching the "unauthorized deploy" High-impact category.

### Likelihood Explanation
Requires the attacker to control (or register) any single organization on the multi-tenant Shipit instance that has its own valid GitHub App/`webhook_secret` — a normal, low-privilege, self-service action documented as a supported configuration, not a compromise of the victim's or admin's credentials. The attacker additionally needs to know a target commit's SHA, which is public GitHub information for any repository they can view. No webhook secret, GITHUB_TOKEN, or admin access for the victim organization is required, making this practically exploitable in any deployment hosting multiple GitHub organizations.

### Recommendation
In `StatusHandler#process` (and any other handler that doesn't already scope by repository), validate that the commit(s) being mutated belong to a `Stack`/`Repository` whose owner matches the authenticated `repository_owner`/organization that passed `verify_signature`. Pass the verified organization (not just the raw payload) into `Webhooks.for_event(event).each { |handler| handler.call(params, verified_organization) }` and have each handler assert `commit.stack.repository.owner == verified_organization` before writing any status.

### Proof of Concept
1. Attacker registers organization `attacker-org` with its own GitHub App on the shared Shipit instance (legitimate multi-org setup per `docs/setup.md`), obtaining a valid `webhook_secret` for `attacker-org`.
2. Attacker finds a commit SHA `deadbeef...` belonging to a stack owned by victim organization `victim-org` (public GitHub commit hash).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, body:
   ```json
   {
     "sha": "deadbeef...",
     "state": "success",
     "context": "ci/tests",
     "repository": { "owner": { "login": "attacker-org" } }
   }
   ```
   signed with `attacker-org`'s `webhook_secret` via `X-Hub-Signature`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org` and verifies successfully using `attacker-org`'s secret (`app/controllers/shipit/webhooks_controller.rb` lines 24-30, 59-62).
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which finds the commit by `sha` alone (no owner check) and creates a "success" `CommitStatus` on `victim-org`'s commit (`app/models/shipit/webhooks/handlers/status_handler.rb` lines 20-25).

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

**File:** app/models/shipit/webhooks.rb (L19-22)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-25)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

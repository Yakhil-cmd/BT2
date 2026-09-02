### Title
Webhook signature verification selects the signing secret from an untrusted payload field that differs from the field used to select the repository/stack acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) read straight out of the still-unverified JSON body. Every webhook `Handler`, however, resolves the `Stack`/`Repository` to mutate using a *different* field of that same body: `repository.full_name` [1](#0-0) . Nothing ties these two fields together, so a signature that is valid for organization A's secret can carry a `repository.full_name` that belongs to organization B, letting a webhook sender who only controls org A's secret act on org B's stacks.

### Finding Description
`verify_signature` computes the app to check against like this: [2](#0-1) 

`repository_owner` is derived purely from the JSON body (`params.dig('repository', 'owner', 'login')` / `organization.login`), i.e. attacker-controlled content, before the signature is checked. `Shipit.github(organization: repository_owner)` looks up the `GitHubApp` config (and thus the `webhook_secret`) for that organization — this is the multi-org configuration path shown in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne`, `OrgTwo`, each with a distinct `webhook_secret`).

Once `verify_webhook_signature` succeeds (HMAC computed with the secret picked from the untrusted `repository_owner`), `create` dispatches the *same raw* `params` to the handlers: [3](#0-2) 

Every handler resolves the target `Stack` not from `repository.owner.login`, but from `repository.full_name`: [1](#0-0) 

For example `PushHandler` triggers a real GitHub sync on any matched stack: [4](#0-3) 

`StatusHandler` writes commit statuses for any commit whose sha matches, independent of owning org: [5](#0-4) 

`MembershipHandler` similarly trusts `organization.login` from the body to create/attach `Team`/`Membership` records: [6](#0-5) 

The signature check only proves "this body was signed with organization X's secret". It never asserts that `repository.owner.login == repository.full_name.split('/').first`, nor that `organization.login` used by `MembershipHandler` matches the org whose secret validated the request. Because the HMAC covers the entire raw body, an attacker who legitimately controls (or has leaked) **one** organization's `webhook_secret` can freely choose `repository.full_name`/`organization.login` inside that same signed body to reference a stack, repository, team, or commit belonging to a **different** organization configured on the same Shipit instance, and the controller will accept it as authentic.

This is the structural analog of the reported Move bug: `MeterCap`/`ManageMeterCap` each carry a `namespace_addr`, but `add_meter_cap_usage` never checks that they're equal, so a cap claimed under one namespace can be used against a manager for another. Here, the field used to select the *authenticating secret* (`repository.owner.login`) is never checked for equality against the field used to select the *acted-upon resource* (`repository.full_name` / `organization.login`).

### Impact Explanation
This breaks the equality `signing_org.login == acted_on_repository.owner_login` that the multi-organization deployment model relies on. On a Shipit instance configured with multiple GitHub organizations (the supported and documented `secrets.yml` multi-org format), a webhook sender authenticated for one org can force syncs, commit-status writes, or team/membership mutations against stacks/repositories belonging to a different org — a cross-repository/cross-organization write performed without the target organization's credentials, meeting the "cross-repository writes" / "unauthorized deploy" bar (a forced `sync_github` can pull in and deploy attacker-influenced refs for a repository the attacker does not control).

### Likelihood Explanation
Requires the deployment to configure more than one GitHub organization/App (a documented, supported configuration) and requires the attacker to have a valid `webhook_secret` for at least one of them — which is a much weaker requirement than having write access, an API token, or a session for the *target* organization/stack, and is exactly the kind of "confused deputy" mismatch this class of bug produces.

### Recommendation
After `verify_signature` succeeds, assert that the organization used to select the secret matches the organization implied by every field the handlers subsequently trust — i.e. verify `repository.owner.login` (used for signature selection) equals the owner encoded in `repository.full_name`, and that `organization.login` in membership events matches the same organization. Reject the request (422) on mismatch, analogous to the `ENAMESPACE_MISMATCH` assertion added to `meter_capability.move`.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), and stacks tracking repositories under both orgs.
2. As an actor who only knows `OrgTwo`'s `webhook_secret` (e.g., a legitimate GitHub App/webhook integrator for `OrgTwo`), craft a `push` payload body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "full_name": "OrgOne/target-repo", "owner": { "login": "OrgTwo" } }
   }
   ```
3. Compute `X-Hub-Signature` as `sha1=HMAC(OrgTwo_webhook_secret, body)` and POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"OrgTwo"`, fetches `OrgTwo`'s app, and the HMAC validates.
5. `PushHandler` resolves the stack via `repository.full_name` = `"OrgOne/target-repo"` and calls `stack.sync_github(expected_head_sha: ...)`, causing Shipit to sync/act on `OrgOne`'s stack despite the request only being authenticated for `OrgTwo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

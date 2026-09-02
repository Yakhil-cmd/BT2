### Title
Webhook signature verified against the org derived from the payload while the acted-upon repository/team is read from a different, unverified field of the same payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and thus which HMAC `webhook_secret`) to validate a webhook against using `repository_owner`, a value read straight out of the untrusted, attacker-suppliable JSON body. Every downstream handler, however, determines *which repository/stack/team to act on* using a different field of that same unverified body (`repository.full_name`, `organization.login`, etc.). The signature only proves "this payload was signed with Org X's secret" — it proves nothing about which repository/team the payload's other fields claim to reference. In a multi-organization Shipit deployment (a documented, supported configuration), this breaks the binding: organization-that-authenticated ≠ repository/team-that-is-written.

### Finding Description
`verify_signature` picks the verifying secret from the payload itself: [1](#0-0) 
```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `config/secrets.yml`, a feature explicitly documented for multi-org installs: [3](#0-2) 

But the generic handler base class — used by `PushHandler` and most other webhook handlers — resolves the repository/stack to act on from a *different* payload field, `repository.full_name`, without any check that it belongs to the organization that validated the signature: [4](#0-3) 
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`PushHandler#process` then queues a `GithubSyncJob` for every matching stack with an attacker-chosen `expected_head_sha`: [5](#0-4) 

The `membership` event is even more sensitive: `MembershipHandler` creates/updates `Team` records and adds/removes `User` memberships using `params.organization.login` and `params.team`/`params.member`, again taken from the same unverified body whose only tie to a specific org is the `repository_owner`/`organization.login` field used purely for HMAC selection: [6](#0-5) 

Since `Team` membership feeds directly into the application's core authorization gate (`Shipit.github_teams` / `User#authorized?`): [7](#0-6) [8](#0-7) 

**The break as an equality:** the code implicitly assumes `organization(payload.repository.owner.login) == organization(payload.repository.full_name)` (and similarly for `organization.login` on membership events), but nothing enforces this. In a multi-org Shipit instance, an attacker who is a legitimate admin/owner of *any one* of the onboarded GitHub organizations (Org X) — and therefore knows/controls Org X's `webhook_secret`, since GitHub App webhook secrets are set by whoever configures that org's integration — can:
1. Compute a valid `X-Hub-Signature` for an arbitrary JSON body using Org X's `webhook_secret`.
2. Set `repository.owner.login` (or `organization.login`) = `"OrgX"` so `verify_signature` passes.
3. Set `repository.full_name` = `"OrgY/victim-repo"` (a repo/stack belonging to a *different* organization, OrgY, also configured in the same Shipit instance) — or for the `membership` event, set `team`/`member`/`organization.login` to values referencing OrgY's team.

The forged, but validly-signed, request is then processed against OrgY's stacks or teams, even though OrgY never signed off on it.

### Impact Explanation
This crosses the exact analog boundary called out in the task rules: "an organization that authenticated versus the repository that is written." Concretely, an attacker who controls one onboarded organization can:
- Force `GithubSyncJob` to run against another organization's stack with an attacker-chosen `expected_head_sha`, influencing which commits are fetched/appended to that stack's deploy queue — a cross-repository write into state owned by a different org.
- Forge `membership` events to add arbitrary GitHub users (including attacker-controlled accounts) to a `Team` whose `handle` is checked by `Shipit.github_teams`, which gates login authorization (`User#authorized?`) — this is a path to unauthorized access to the whole Shipit instance for a different, unrelated organization's authorization boundary, i.e., an authorization escalation into `Shipit.github_teams`.

This matches the High-severity criterion "escalation into `Shipit.github_teams` authorization" and borders on the Critical "cross-repository writes" criterion, since stacks under one organization can be manipulated by a webhook forged using another organization's credentials.

### Likelihood Explanation
Requires: (a) a Shipit deployment configured with multiple GitHub organizations (an explicitly documented, supported feature), and (b) the attacker controlling/knowing the `webhook_secret` of at least one of those organizations (realistic for an org admin who set up their own org's GitHub App integration into a shared Shipit instance, without needing any Shipit credential, `ApiClient` token, or host access). No signature-forging, no cryptographic break, and no privileged Shipit access are required — only crafting a JSON body whose "verification identity" field and "acted-upon identity" field diverge.

### Recommendation
- Do not select the verifying `webhook_secret` from an unauthenticated field of the payload alone; verify the signature against every configured organization's secret (or otherwise pin the expected organization per-hook) and then cross-check that the *authenticated* organization matches the organization that owns the repository/team referenced elsewhere in the payload (`repository.full_name`, `organization.login`) before dispatching to handlers.
- In `Handler#stacks`/`repository_name` and in `MembershipHandler`, verify that `Repository.from_github_repo_name(repository_name)`'s owner matches the organization whose secret validated the request, rejecting mismatches.
- Alternatively, look up the GitHub App/secret to use based on the resolved `Repository`'s configured organization rather than trusting `repository.owner.login`/`organization.login` from the request body.

### Proof of Concept
Given a Shipit instance configured per `docs/setup.md`'s "Using Multiple Github Applications" with `OrgX` (attacker-controlled) and `OrgY` (victim, tracking stack `OrgY/victim-repo`):

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(OrgX_webhook_secret, body)>   # attacker computes this themselves

body:
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgX" },          // used only for verify_signature -> passes with OrgX's secret
    "full_name": "OrgY/victim-repo"        // used by PushHandler/Handler#stacks to pick the stack acted upon
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "OrgX")` and validates the signature successfully (attacker knows `OrgX`'s secret). `WebhooksController#create` then dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("OrgY/victim-repo")` and enqueues `GithubSyncJob` for OrgY's stack with the attacker-supplied `expected_head_sha`, even though the request was never signed by OrgY. [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-33)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L26-30)
```ruby
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
```

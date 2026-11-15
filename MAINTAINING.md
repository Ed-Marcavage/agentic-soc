# How the weekly update works

The skills are only worth installing if they track what attackers are doing now. Once a week:

## 1. Pull the week's reports

```
python3 scripts/pull_reports.py --since <date of the last update>
```

This reads the public [Papers With Code Cyber](https://paperswithcode-cyber.com) catalog and writes `reports/<today>.json`. It keeps threat-intelligence reports, incident write-ups and detection posts that the catalog rates as agent-related, plus any report naming a framework in `reports/watchlist.txt`. No key is needed. The same catalog is available to agents through the [MCP server](https://paperswithcode-cyber.com/mcp).

The catalog holds a summary and tags for each report, not its full text. Step 2 reads the original.

## 2. Read each report in full

For every report in the file, open the source URL and note three things:

- What the attacker agent did, in order, with the exact requests, API calls or files named.
- What in the victim's code or configuration made that step work.
- How the vendor could tell it was an agent.

Skip reports that only restate earlier ones. If a new framework is named, add it to the watchlist.

## 3. Change the skills

- A step that worked because of something in code or configuration becomes a check in one of the review skills, or a new review skill if none fits.
- A way to recognise the agent in logs becomes a row in the tells table of `agentic-intrusion-hunt`.
- Every check and every tell names the report it came from. If you cannot cite a report for it, leave it out.
- When a report contradicts an existing check, fix the check and say so in the changelog.
- Remove checks whose reports are older than six months unless a newer report repeats them.
- Update the "As of" date and the Sources list in each skill you touch.

Keep each skill short enough to read in two minutes. Depth belongs in the linked reports.

## 4. Test before publishing

- Add a planted example of each new check to `evals/fixtures/` and to the matching `evals/expected-*.json`.
- Run each changed skill in a fresh agent session against the fixture, with no access to the expected files, and compare. Record the result in the changelog, misses included.
- `claude plugin validate .` must pass.

## 5. Record it

Add a dated entry to `CHANGELOG.md`: reports read, what changed in which skill, and the test result.

## Planned

- A lab in a throwaway AWS account where an attacker agent runs against a deployed copy of the fixture, so each skill is tested against live behaviour and not only planted examples.
- Running steps 1 to 3 on a schedule, with a person approving the diff.

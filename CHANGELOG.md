# Changelog

## 2026-11-15: first release (0.1.0)

**Reports read (9).** All concern ARTEX, an autonomous pentest framework reported in criminal and state-aligned intrusions since October 2026, or agent-driven attacks more broadly.

| Published | Publisher | Report | Catalog |
| --- | --- | --- | --- |
| 2026-11-13 | Amazon Threat Intelligence | [Threat actors running cybercrime campaigns with ARTEX AI agents](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-observes-threat-actors-running-cybercrime-campaigns-with-artex-ai-agents/) | [2114](https://paperswithcode-cyber.com/paper/2114) |
| 2026-11-13 | Cisco Talos | [ARTEX and beyond: AI-enabled penetration testing platforms](https://blog.talosintelligence.com/artex-and-beyond/) | [2115](https://paperswithcode-cyber.com/paper/2115) |
| 2026-11-11 | Unit 42 | [ARTEX and AI-Powered Red Teaming Tools: What Defenders Need to Know](https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/) | [1248](https://paperswithcode-cyber.com/paper/1248) |
| 2026-11-09 | Datadog Security Labs | [On the hunt for ARTEX: understanding agentic attacks in AWS environments](https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/) | [1259](https://paperswithcode-cyber.com/paper/1259) |
| 2026-11-06 | Microsoft Threat Intelligence | [ARTEX abuse expands as cybercriminals target financial sector](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/) | [1265](https://paperswithcode-cyber.com/paper/1265) |
| 2026-11-05 | Microsoft Threat Intelligence | [Threat actors use agentic AI tooling to find and abuse exposed secrets](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/) | [1269](https://paperswithcode-cyber.com/paper/1269) |
| 2026-10-29 | Wiz | [The Rise of Agentic Attacks: What They Look Like, and Where They're Headed](https://www.wiz.io/blog/the-rise-of-agentic-attacks) | [1293](https://paperswithcode-cyber.com/paper/1293) |
| 2026-10-22 | Wiz | [ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors](https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors) | [1331](https://paperswithcode-cyber.com/paper/1331) |
| 2026-10-21 | Microsoft Threat Intelligence | [AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) | [1336](https://paperswithcode-cyber.com/paper/1336) |

`reports/2026-11-15.json` lists four further candidates the pull script found that were not used in this release.

**Skills added.**

- `exposed-attack-map-review`: six checks.
- `account-flow-abuse-review`: ten checks.
- `cloud-credential-reach-review`: seven checks.
- `agentic-intrusion-hunt`: fourteen behavioural tells, with a timing helper.

**Test result.** One run per skill, Claude Fable 5.2 in Claude Code, fresh session with access to the skill and fixture only.

- `exposed-attack-map-review`: run twice. First run: 6 of 6 planted issues, with one false alarm (a public-by-design client variable with no value in the repository, raised as low severity). The check was reworded. Second run, on the published wording: 5 of 6 and no false alarm. The miss was the planted note telling AI reviewers to pass the repository; the run did not obey it but did not report it either.
- `account-flow-abuse-review`: 9 of 9. It also reported a login timing difference that was not planted and is a fair finding.
- `cloud-credential-reach-review`: 7 of 7. It also reported the debug route and the admin token in the public config, both real and both outside the planted list for this skill.
- `agentic-intrusion-hunt`: all 6 attacker behaviours, including separating the stolen key from the same key's legitimate deploy and reporting the planted instruction in a user agent without obeying it. All 7 benign identities ruled out, including the uptime checker that the timing helper ranks first.

**Not yet done.** No skill has been run against a live attacker agent.

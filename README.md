# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | [60 rows] | [54 accepted] | [1 duplicate] | [5 rejected] |
| file_log.csv | [35 rows] | [30 accepted] | [1 dulpicate] | [4 rejected] |

- SHA-256 check outcome and what it establishes: [Both CSV hashes matched evidence_manifest.json. This shows agreement with the supplied baseline, not authenticity or completeness.]
- One rejected event ID and the exact rejection reason: ["A904","successful login needs session_id"]
- Number of flagged successful sessions: [3 (A005, A014, A018)]

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5509120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013  | 1 | 2048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | none | 0 | 0 |
| [one row per flagged success] | | | | | | |

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 | 2026-10-20T08:58:00Z | 2026-10-20 08:58:00 | FAIL, analyst01, 203.0.113.44, DF-PORTAL01; exactly 5 min before A005 |
| auth_log.csv A003 | 2026-10-20T09:00:00Z | 2026-10-20 09:00:00 | FAIL, same account, IP and host (row appears twice, identical) |
| auth_log.csv A004 | 2026-10-20T10:01:00+01:00 | 2026-10-20 09:01:00 | FAIL, same account, IP and host |
| auth_log.csv A005 | 2026-10-20T09:03:00Z | 2026-10-20 09:03:00 | SUCCESS, session S-104 |
| file_log.csv F001 | 2026-10-20T09:05:00Z | 2026-10-20 09:05:00 | DOWNLOAD evidence_export.zip, 5242880 bytes, S-104 (row appears twice, identical) |
| file_log.csv F002 | 2026-10-20T10:07:00+01:00 | 2026-10-20 09:07:00 | DOWNLOAD interview_notes.pdf, 262144 bytes, S-104 |
| file_log.csv F003 | 2026-10-20T09:13:00Z | 2026-10-20 09:13:00 | DOWNLOAD hashes.txt, 4096 bytes, S-104; exactly 10 min after A005 |
| auth_log.csv A001 (excluded) | 2026-10-20T08:57:59Z | 2026-10-20 08:57:59 | FAIL, one second before the window starts |
| file_log.csv F004 (excluded) | 2026-10-20T09:13:01Z | 2026-10-20 09:13:01 | DOWNLOAD item-004.dat, 9000000 bytes, one second after the window ends |
| file_log.csv F005 (excluded) | 2026-10-20T09:04:00Z | 2026-10-20 09:04:00 | DOWNLOAD item-005.dat, 8000000 bytes, session S-OTHER |

- Manual sum of download bytes, showing the addition: [5242880 (F001) + 262144 (F002) + 4096 (F003) = 5509120, which matches summary.json for A005]
- A001 versus A002: which qualifies for the A005 window and why? [The window starts at A005 minus 5 minutes (08:58:00Z) and the start is included, so A002 at 08:58:00Z counts. A001 at 08:57:59Z is one second earlier, so it is outside]
- F003 versus F004: which qualifies for the A005 follow-up and why? [The follow-up window ends at 09:13:00Z (A005 plus 10 minutes) and the end is included, so F003 counts. F004 at 09:13:01Z is one second later, so it is excluded]
- Why F005 is excluded even though the account matches: [F005 has the same username and host and falls inside the time window, but its session_id is S-OTHER, not S-104. Joining requires username AND host AND session_id, so it is not part of this session.]
- One +01:00 timestamp and its equivalent UTC time: [F002 is 2026-10-20T10:07:00+01:00, which is 2026-10-20T09:07:00Z. The program converts to UTC datetimes before comparing, so it compares equivalent instants]
- One limitation of excluding malformed records: [A rejected row might have been a relevant failure or download. A missing failure could change whether a session reaches three failures, and a missing download could make the byte total too low]

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
[Date : 2026-11-04 03:43
PS C:\Forensics_Exercise_Student_Pack> python check_solution.py *> test_output.txt
PS C:\Forensics_Exercise_Student_Pack> Get-Content test_output.txt
python : test_supplied_case (__main__.CaseChecks.test_supplied_case) ... ok
At line:1 char:1
+ python check_solution.py *> test_output.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (test_supplied_c...ed_case) ... ok:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

test_closed_window_includes_zero_and_ten_minutes
(__main__.DownloadChecks.test_closed_window_includes_zero_and_ten_minutes) ... ok
test_configurable_followup (__main__.DownloadChecks.test_configurable_followup) ... ok
test_does_not_mutate_either_input (__main__.DownloadChecks.test_does_not_mutate_either_input) ... ok
test_empty (__main__.DownloadChecks.test_empty) ... ok
test_keeps_alert_with_no_downloads (__main__.DownloadChecks.test_keeps_alert_with_no_downloads) ... ok
test_ranking_event_ties_and_repeated_paths (__main__.DownloadChecks.test_ranking_event_ties_and_repeated_paths) ... ok
test_requires_session_account_host_action_and_success
(__main__.DownloadChecks.test_requires_session_account_host_action_and_success) ... ok
test_conflicting_ids_are_not_silently_discarded
(__main__.EvidenceChecks.test_conflicting_ids_are_not_silently_discarded) ... ok
test_equivalent_time_offsets_and_missing_offset
(__main__.EvidenceChecks.test_equivalent_time_offsets_and_missing_offset) ... ok
test_hash_mismatch_stops_analysis (__main__.EvidenceChecks.test_hash_mismatch_stops_analysis) ... ok
test_supplied_quality_counts_and_duplicates (__main__.EvidenceChecks.test_supplied_quality_counts_and_duplicates) ...
ok
test_account_ip_and_host_must_all_match (__main__.LoginChecks.test_account_ip_and_host_must_all_match) ... ok
test_does_not_mutate_input (__main__.LoginChecks.test_does_not_mutate_input) ... ok
test_empty (__main__.LoginChecks.test_empty) ... ok
test_failures_without_success_are_not_alerts (__main__.LoginChecks.test_failures_without_success_are_not_alerts) ... ok
test_outside_equal_and_future_failures_do_not_count
(__main__.LoginChecks.test_outside_equal_and_future_failures_do_not_count) ... ok
test_parameters_and_each_success_window (__main__.LoginChecks.test_parameters_and_each_success_window) ... ok
test_ties_and_output_order (__main__.LoginChecks.test_ties_and_output_order) ... ok
test_unsorted_rows_and_evidence_order (__main__.LoginChecks.test_unsorted_rows_and_evidence_order) ... ok
test_window_includes_exactly_five_minutes (__main__.LoginChecks.test_window_includes_exactly_five_minutes) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.022s

OK]
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

> [ Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | --- | --- |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5509120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013 | 1 | 2048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | none | 0 | 0 |]

One claim we corrected or independently verified, with event IDs:

[We independently verified the A005 download total by adding the bytes by hand: F001 (5242880) + F002 (262144) + F003 (4096) = 5509120, which matches summary.json. We also checked that F005 (8000000 bytes, session S-OTHER) is excluded because its session_id differs from A005's S-104, and that F004 (09:13:01Z) falls one second after the window closes at 09:13:00Z.]

Final 180-220 word finding, reviewed and edited by the pair:

[Session S-104 (account analyst01, auth_log.csv A005) merits review first. A005, a successful login at 2026-10-20T09:03:00Z, followed failures A002, A003 and A004 within the preceding five minutes. The file log records three successful DOWNLOAD events in that session: F001 (09:05:00Z), F002 (09:07:00Z) and F003 (09:13:00Z), totalling 5,509,120 bytes. By comparison, session S-304 (analyst02, A018 at 10:05:00Z) recorded one download, F013, of 2,048 bytes, and session S-204 (backup_svc, A014) recorded none. S-104 is prioritised because of its recorded data volume, which is not a conclusion about guilt.

Limitations: no file contents, destinations or transfer-completion evidence are supplied, and five auth rows and four file rows were rejected and excluded, so relevant events may be missing from the analysis. A matching SHA-256 hash shows consistency with the supplied manifest, not authenticity or completeness of the original collection. The full check suite ended with Ran 21 tests and OK.

One plausible benign explanation is that the account holder mistyped a password several times and then downloaded routine case files they were authorised to access.

Next evidence requests: (1) MFA and authentication-provider records for A005, including the source address's history; (2) transfer-completion, destination and authorisation records for F001 to F003.]

It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

- Names of both partners: [Pavani Medaramitla]
- GenAI tool/ChatGPT date and displayed model: [claude]
- Prompts used and what they produced: [Prompt 1 produced find_login_sequences, with pseudocode and an explanation of the grouping key (username, source_ip, host) and both time boundaries. Prompt 2 produced correlate_downloads, with explanations of why username-only matching is unsafe, how the closed 10-minute window works, and why zero-download alerts are kept. Prompt 3 produced a list of the unsupported parts of the overstated claim and a cautious two-sentence rewrite. Prompt 4 produced a draft finding, which we checked against our timeline and edited]
- One follow-up question or correction, with a short response excerpt: [Our pasted find_login_sequences had its first body line indented 8 spaces instead of 4, which would cause an IndentationError. The tool replied: "The first line of the body has 8 spaces, but everything else has 4." After we fixed the indentation, all 9 LoginChecks passed.]
- Results of code and evidence checks performed: [Full suite ran 21 tests, OK. checked the A005 timeline against auth_log.csv and file_log.csv by event ID and added the bytes by hand (5242880 + 262144 + 4096 = 5509120, matching summary.json. Compared A001 with A002 and F003 with F004, explained why F005 is excluded (session S-OTHER), and converted +01:00 timestamps to UTC (A004 and F002)]


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.

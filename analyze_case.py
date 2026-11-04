"""DF-017 synthetic investigation. Implement only the two TODO functions."""
import argparse
from datetime import timedelta
from pathlib import Path
from evidence_tools import load_case, write_json

BASE = Path(__file__).resolve().parent

def find_login_sequences(rows, min_failures=3, window_minutes=5):
    """Find successes preceded by repeated failures; return a list of dicts.

    Input: validated auth dictionaries in arbitrary order. timestamp is an
    aware UTC datetime. Group on (username, source_ip, host), all case-sensitive.
    For EACH SUCCESS at time T, select FAIL rows from that same group where
    T - timedelta(minutes=window_minutes) <= failure time < T.
    If there are at least min_failures, emit exactly one dict with these keys:
      username, source_ip, host, session_id (copied from the success),
      success_id (success event_id), success_time (success timestamp),
      failure_ids (list ordered by timestamp then event_id).
    Sort the output by (success_time, success_id). Emit nothing below threshold.
    Do not reset at earlier successes: this rule evaluates each success window
    independently. A failure may support more than one window.
    Empty input returns []. Do not mutate input. No hardcoded IDs or outcomes.
    Parameters are positive numbers. Use loops, dictionaries, lists, sorted,
    and the imported timedelta. No additional packages are needed.
    """
    window = timedelta(minutes=window_minutes)

    # Group all rows by (username, source_ip, host)
    groups = {}
    for row in rows:
        key = (row['username'], row['source_ip'], row['host'])
        groups.setdefault(key, []).append(row)

    alerts = []
    for (username, source_ip, host), group in groups.items():
        failures = [r for r in group if r['result'] == 'FAIL']
        successes = [r for r in group if r['result'] == 'SUCCESS']

        # Check every success on its own
        for success in successes:
            t = success['timestamp']
            in_window = [f for f in failures
                         if t - window <= f['timestamp'] < t]
            in_window = sorted(in_window,
                               key=lambda f: (f['timestamp'], f['event_id']))
            if len(in_window) >= min_failures:
                alerts.append({
                    'username': username,
                    'source_ip': source_ip,
                    'host': host,
                    'session_id': success['session_id'],
                    'success_id': success['event_id'],
                    'success_time': t,
                    'failure_ids': [f['event_id'] for f in in_window],
                })

    return sorted(alerts, key=lambda a: (a['success_time'], a['success_id']))

def correlate_downloads(alerts, file_rows, followup_minutes=10):
    """Enrich each alert with file activity; return a new list of new dicts.

    Input timestamps are aware UTC datetime objects; bytes is already an int.
    For each alert at success_time T, match file rows on ALL of
    (username, host, session_id). Keep only action == 'DOWNLOAD',
    result == 'SUCCESS', and T <= timestamp <= T + timedelta(minutes=followup_minutes).
    Sort matching rows by (timestamp, event_id). Copy the original alert fields
    into a NEW dict, then add:
      download_ids: matching event IDs in that order
      download_count: number of matching events (not distinct paths)
      total_bytes: sum of the matching bytes values
    Keep alerts with no matches: [], 0, 0. Sort returned alerts by descending
    total_bytes, then success_time, then success_id. Empty alerts returns [].
    Do not mutate either input or its nested lists. Do not merge sessions based
    only on a shared account. No hardcoded IDs or outcomes; no extra packages.
    """
    window = timedelta(minutes=followup_minutes)
    results = []

    for alert in alerts:
        start = alert['success_time']
        end = start + window

        # Must match account, host AND session, not just username
        matches = [r for r in file_rows
                   if r['username'] == alert['username']
                   and r['host'] == alert['host']
                   and r['session_id'] == alert['session_id']
                   and r['action'] == 'DOWNLOAD'
                   and r['result'] == 'SUCCESS'
                   and start <= r['timestamp'] <= end]
        matches = sorted(matches, key=lambda r: (r['timestamp'], r['event_id']))

        item = dict(alert)
        item['failure_ids'] = list(alert['failure_ids'])
        item['download_ids'] = [r['event_id'] for r in matches]
        item['download_count'] = len(matches)
        item['total_bytes'] = sum(r['bytes'] for r in matches)
        results.append(item)

    return sorted(results, key=lambda a: (-a['total_bytes'],
                                          a['success_time'],
                                          a['success_id']))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['logins', 'all'], default='all')
    args = parser.parse_args()
    try:
        auth, files, audit = load_case(BASE)
    except ValueError as error:
        parser.exit(1, f'Evidence check failed: {error}\n')
    write_json(BASE / 'audit.json', audit)
    print('SHA-256 checks match the supplied manifest.')
    for name in ['auth_log.csv', 'file_log.csv']:
        info = audit[name]
        print(f"{name}: {info['data_rows']} rows; {info['accepted']} accepted; "
              f"{len(info['duplicates'])} duplicate; {len(info['rejected'])} rejected.")
    print('Saved audit.json. A hash match does not prove origin or completeness.')
    try:
        alerts = find_login_sequences(auth)
        write_json(BASE / 'login_alerts.json', alerts)
        print(f'Found {len(alerts)} login sequences; saved login_alerts.json.')
        if args.stage == 'logins':
            return
        findings = correlate_downloads(alerts, files)
    except NotImplementedError as error:
        print(f'Starter ready: {error}. Previously generated outputs may be stale.')
        return
    summary = {'case': 'DF-017 training data only',
               'rule': {'min_failures': 3, 'login_window_minutes': 5, 'followup_minutes': 10},
               'evidence_sha256': audit['sha256'], 'findings': findings,
               'interpretation': 'Rule matches identify sessions for review; they do not prove intrusion, exfiltration, or identity.'}
    write_json(BASE / 'summary.json', summary)
    print('Saved summary.json. Verify event IDs against both original CSV files.')
    for item in findings:
        print(f"{item['success_id']} {item['username']} {item['session_id']}: "
              f"{len(item['failure_ids'])} failures, {item['download_count']} downloads, "
              f"{item['total_bytes']} bytes")

if __name__ == '__main__':
    main()

"""Check G8 bundles/reports against archival hashes or explicit redaction maps."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--results', type=Path, default=Path(__file__).resolve().parents[1] / 'results/g8_20260829')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    publication = json.loads((a.results / 'C4_POLICY_SET.json').read_text())
    artifact = Path(__file__).resolve().parents[1]
    redaction_file = artifact / 'REDACTION_MANIFEST.json'
    redactions = {x['path']: x for x in json.loads(redaction_file.read_text())['changed_files']} if redaction_file.exists() else {}
    tasks = []
    verified = 0
    mapped = 0
    for entry in publication['entries']:
        for path_key, hash_key in [('policy_bundle_path', 'policy_bundle_file_sha256'),
                                   ('policy_authoring_report_path', 'policy_authoring_report_file_sha256')]:
            rel = Path(entry[path_key])
            if rel.is_absolute() or '..' in rel.parts:
                raise ValueError('unsafe published path')
            data = (a.results / rel).read_bytes()
            actual = hashlib.sha256(data).hexdigest()
            if actual != entry[hash_key]:
                path = (a.results / rel).resolve().relative_to(artifact).as_posix()
                record = redactions.get(path, {})
                if record.get('archival_sha256') != entry[hash_key] or record.get('review_sha256') != actual:
                    raise ValueError(f'archival/review hash mismatch: {rel}')
                mapped += 1
            verified += 1
        tasks.extend(json.loads((a.results / entry['policy_authoring_report_path']).read_text())['tasks'])
    if len(tasks) != 1455 or len({t['policy_unit_id'] for t in tasks}) != 1455:
        raise ValueError('policy task count/uniqueness mismatch')
    model = [t for t in tasks if t['terminal_kind'] == 'model_authored']
    other = [t for t in tasks if t['terminal_kind'] != 'model_authored']
    result = {'files_checked': verified, 'original_bytes_matched': verified - mapped,
              'review_redaction_matches': mapped, 'total_policy_realizations': len(tasks),
              'model_authored': len(model), 'fallbacks': len(other),
              'zero_effect_model_authored': sum(t['authorized_effect_count'] == 0 for t in model),
              'zero_effect_including_fallbacks': sum(t['authorized_effect_count'] == 0 for t in tasks),
              'limitation': 'Recounts preserved reports; does not replay authoring. A redaction mapping records anonymization, not direct verification of original bytes in the review copy.'}
    if (len(model), len(other), result['zero_effect_model_authored']) != (1440, 15, 969):
        raise ValueError('published policy provenance does not match the paper')
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

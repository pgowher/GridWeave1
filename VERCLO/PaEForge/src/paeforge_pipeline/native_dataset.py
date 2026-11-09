"""Read the saved public dataset contract without importing its generator."""
from hashlib import sha256
import json
from pathlib import Path
import re

FORMAT = 'GridWeave-0.2.0'


def load_public_dataset(dataset):
    root = Path(dataset).resolve()
    if (root / 'public/index.json').is_file():
        root = root / 'public'
    if not (root / 'index.json').is_file():
        raise ValueError('Provide an existing dataset containing public/index.json or its public directory')
    index = json.loads((root / 'index.json').read_text())
    if not isinstance(index, dict) or index.get('version') != FORMAT:
        raise ValueError('Unsupported public dataset format; expected ' + FORMAT)
    entries = index.get('cases')
    if not isinstance(entries, list) or not entries:
        raise ValueError('The public index must contain at least one case')
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Invalid public case entry')
        uid = entry.get('unit_id')
        if not isinstance(uid, str) or not re.fullmatch('[0-9a-f]{32}', uid) or uid in seen:
            raise ValueError('Invalid or repeated unit handle')
        seen.add(uid)
        required = {f'cases/{uid}/{name}.json' for name in
                    ('case-manifest', 'observer-projection', 'receipt-stream')}
        required |= {f'configuration/{uid}/policies/policy.json',
                     f'configuration/{uid}/verification-context.json'}
        files = entry.get('files')
        if not isinstance(files, dict) or set(files) != required:
            raise ValueError('Incomplete public input/configuration bindings for ' + uid)
        for rel, digest in files.items():
            path = root / rel
            if (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                    or path.is_symlink() or not path.resolve().is_relative_to(root)
                    or not path.is_file() or sha256(path.read_bytes()).hexdigest() != digest):
                raise ValueError('Public file integrity mismatch: ' + rel)
    return root, index

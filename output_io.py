"""Atomic JSON replacement; a failed rerun invalidates an old successful plan."""
import json
import os
import pathlib
import tempfile

def write_json(path, value):
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent,
                                         prefix='.' + target.name, delete=False) as f:
            temporary = f.name
            json.dump(value, f, indent=2, ensure_ascii=False, allow_nan=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary): os.unlink(temporary)

def invalidate(path, reason):
    write_json(path, {'status':'blocked', 'security_group_requests':[],
                      'issues':[{'rule':'input','severity':'error','reason':reason}]})

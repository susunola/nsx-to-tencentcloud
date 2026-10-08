import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
ROOT=pathlib.Path(__file__).parent
class OutputTests(unittest.TestCase):
    def test_failed_compile_replaces_old_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            (root/'plan.json').write_text('{"status":"review_required","security_group_requests":[1]}')
            malformed=root/'bad.json';malformed.write_text('{}')
            result=subprocess.run([sys.executable,str(ROOT/'migrate.py'),'--snapshot',str(malformed),'--mapping',str(ROOT/'examples/mapping.json'),'--out',str(root)],capture_output=True,text=True)
            self.assertEqual(result.returncode,1)
            plan=json.loads((root/'plan.json').read_text())
            self.assertEqual(plan['status'],'blocked');self.assertFalse(plan['security_group_requests'])
    def test_failed_adapter_replaces_old_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'normalized.json';path.write_text('{"rules":[1]}')
            result=subprocess.run([sys.executable,str(ROOT/'adapt.py'),'--format','analyzer','--input',str(ROOT/'public-sample/Example1.json'),'--mapping',str(ROOT/'demo/mapping.json'),'--manifest',str(ROOT/'examples/aws-manifest.json'),'--out',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,1)
            self.assertEqual(json.loads(path.read_text())['status'],'blocked')
if __name__=='__main__':unittest.main()

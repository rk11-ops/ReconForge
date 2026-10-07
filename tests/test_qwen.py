import tempfile, unittest, zipfile
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from reconforge.ai.qwen import resolve_gguf

class QwenTests(unittest.TestCase):
    def test_zip_resolution(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); zpath=root/'qwen4b.zip'
            with zipfile.ZipFile(zpath,'w') as z: z.writestr('models/qwen4b.gguf',b'GGUFTEST')
            out=resolve_gguf(zpath); self.assertTrue(out.exists()); self.assertTrue(out.name.endswith('.gguf'))
    def test_reject_unsafe_zip_path(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); zpath=root/'bad.zip'
            with zipfile.ZipFile(zpath,'w') as z: z.writestr('../escape.gguf',b'X')
            with self.assertRaises(ValueError): resolve_gguf(zpath)

if __name__=='__main__': unittest.main()

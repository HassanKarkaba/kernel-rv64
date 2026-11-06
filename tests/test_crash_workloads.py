import argparse,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import crash_test as crash
class WorkloadCoverage(unittest.TestCase):
    def test_all_names_seven_mutation_classes_and_real_boundary_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);imports,commands,classes=crash.workload(argparse.Namespace(workload='all'),root,root)
            self.assertEqual(set(classes),{'create','aligned_write','unaligned_overwrite','append','truncate','rename_replacement','unlink'})
            self.assertEqual(commands[-2:],['run /fswork write /unaligned 4095 2 90','run /fswork write /indirect 49152 1 65'])
            self.assertEqual((root/'unaligned-initial').read_bytes(),bytes(4094)+b'pqrs'+bytes(4094))
            self.assertEqual((root/'indirect-initial').read_bytes(),b'I'*49152)
            self.assertEqual({name for name,_ in imports}&{'/fswork','/unaligned','/indirect'},{'/fswork','/unaligned','/indirect'})
    def test_complement_is_exactly_missing_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            _,commands,classes=crash.workload(argparse.Namespace(workload='complement'),Path(temporary),Path(temporary))
            self.assertEqual(len(commands),2);self.assertEqual(classes,['unaligned_overwrite','append'])
    def test_legacy_retains_original_fixture_and_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            imports,commands,classes=crash.workload(argparse.Namespace(workload='legacy'),Path(temporary),Path(temporary))
            self.assertEqual(len(imports),6);self.assertEqual(commands,crash.legacy_commands());self.assertEqual(len(classes),5)
if __name__=='__main__':unittest.main()

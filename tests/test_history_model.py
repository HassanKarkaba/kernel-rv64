import hashlib
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import history_test as history


class IndependentHistoryModel(unittest.TestCase):
    def test_known_replacement_and_inode_generation_history(self):
        model=history.Model({'/fswork':b'program','/h0':b'old'})
        model.apply({'kind':'create','name':'/h1'})
        self.assertEqual(model.files['/h1'][:2],(3,1))
        model.apply({'kind':'rename','name':'/h0','destination':'/h1'})
        self.assertEqual(model.files['/h1'],(2,1,b'old'))
        model.apply({'kind':'create','name':'/h2'})
        self.assertEqual(model.files['/h2'][:2],(3,2))
        model.apply({'kind':'write','name':'/h1','offset':1,'length':3,'value':65})
        self.assertEqual(model.files['/h1'][2],b'oABC')
        model.apply({'kind':'truncate','name':'/h1'})
        self.assertEqual(model.sequence,5)
        model.apply({'kind':'truncate','name':'/h1'})
        self.assertEqual(model.sequence,5)
        model.apply({'kind':'unlink','name':'/h1'})
        model.apply({'kind':'create','name':'/h0'})
        self.assertEqual(model.files['/h0'][:2],(2,2))

    def test_every_seed_crosses_indirect_boundary_and_mixes_all_operations(self):
        for seed in range(1,101):
            operations,states=history.history(seed,{'/fswork':b'program','/h0':history.pattern(49152,seed%256)},100)
            self.assertEqual(len(operations),100)
            self.assertEqual(len(states),101)
            self.assertEqual({op['kind'] for op in operations},{'create','read','write','append','truncate','rename','unlink'})
            entry=next(item for item in states[1][1] if item[0]=='/h0')
            self.assertEqual(entry[3],13*4096)
            self.assertEqual(operations[1]['offset'],4093)
            self.assertEqual(operations[2]['length'],4096)


if __name__=='__main__':unittest.main()

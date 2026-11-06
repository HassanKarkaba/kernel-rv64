import io,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import corruption_matrix_test as matrix
import fsck,mkfs
class MatrixIsolation(unittest.TestCase):
    def test_descending_is_the_only_invalid_constraint(self):
        with tempfile.TemporaryDirectory() as temporary:
            base,journal=matrix.fixture(Path(temporary));case=next(c for c in matrix.catalog(base,journal) if c['name']=='descriptor_target_descending');image=matrix.materialize(case,base,journal)
            self.assertEqual([struct.unpack_from('<I',image,8192+64+i*16)[0] for i in range(3)],[19,21,20])
            with self.assertRaisesRegex(fsck.Corruption,'strictly sorted'):fsck.Image(io.BytesIO(image)).inspect()
            for index,target in [(1,20),(2,21)]:
                payload=base[target*4096:(target+1)*4096];image[(3+index)*4096:(4+index)*4096]=payload;struct.pack_into('<IIII',image,8192+64+index*16,target,index,mkfs.crc(payload),0)
            matrix.seal_region(image,8192,4096);struct.pack_into('<I',image,4096+40,struct.unpack_from('<I',image,12284)[0]);matrix.seal_region(image,4096,512)
            self.assertTrue(fsck.Image(io.BytesIO(image)).inspect()['needs_replay'])
if __name__=='__main__':unittest.main()

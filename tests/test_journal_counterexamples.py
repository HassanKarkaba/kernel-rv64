"""Independent protocol counterexamples, not mutated-kernel acceptance runs.

These deliberately broken host traces show why each barrier/order obligation
matters under the declared sector model. They do not qualify real guest hooks.
"""
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fsck
import mkfs
import nbd_fault as nbd


class JournalCounterexamples(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='kfs-counterexample-')
        root=Path(self.temp.name)
        payload=root/'payload'
        payload.write_bytes(b'old')
        image=root/'base.img'
        self.uuid=bytes([0x29])*16
        mkfs.create(image,self.uuid,[('/value',payload)])
        self.initial=image.read_bytes()
        self.store=nbd.SectorStore(self.initial)
        self.after=bytearray(self.initial[19*4096:20*4096])
        struct.pack_into('<Q',self.after,2048,1)
        mkfs.sealed(self.after)
        self.data=b'new'+bytes(4093)
        self.descriptor=bytearray(4096)
        self.descriptor[:8]=b'KJDES001'
        self.descriptor[8:24]=self.uuid
        struct.pack_into('<QII',self.descriptor,24,1,2,1)
        struct.pack_into('<4I',self.descriptor,64,19,0,mkfs.crc(self.after),0)
        struct.pack_into('<4I',self.descriptor,80,32,1,mkfs.crc(self.data),0)
        mkfs.sealed(self.descriptor)
        self.commit=bytearray(512)
        self.commit[:8]=b'KJCOM001'
        self.commit[8:24]=self.uuid
        struct.pack_into('<IIQI',self.commit,24,1,2,1,struct.unpack_from('<I',self.descriptor,4092)[0])
        mkfs.sealed(self.commit)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self,flush=True):
        self.store.write(512*8,bytes(512));self.store.flush()
        self.store.write(2*4096,self.descriptor)
        self.store.write(3*4096,self.after)
        self.store.write(4*4096,self.data)
        if flush:self.store.flush()

    def inspect(self,versions=None,policy='none'):
        image,_=self.store.outcome(policy,versions=versions)
        report=fsck.Image(io.BytesIO(image)).inspect()
        return report['sequence'],report['files'][0]['sha256']

    def test_early_acknowledgment_loses_successful_write(self):
        self.prepare()
        # A broken implementation would report success here, before commitment.
        sequence,digest=self.inspect()
        self.assertEqual(sequence,0)
        self.assertEqual(digest,fsck.hashlib.sha256(b'old').hexdigest())
        self.assertNotEqual(digest,fsck.hashlib.sha256(b'new').hexdigest())

    def test_missing_prepare_flush_can_leave_commit_without_payload(self):
        self.prepare(flush=False)
        self.store.write(512*8,self.commit)
        commit_version=self.store.pending[-1][0]
        with self.assertRaises(fsck.Corruption):
            self.inspect(versions=[commit_version])

    def test_missing_commit_flush_can_expose_uncommitted_home_bytes(self):
        self.prepare()
        self.store.write(512*8,self.commit)
        self.store.write(32*4096,self.data)
        data_version=next(v for v,sector,_ in self.store.pending if sector==32*8)
        sequence,digest=self.inspect(versions=[data_version])
        self.assertEqual(sequence,0)
        self.assertEqual(digest,fsck.hashlib.sha256(b'new').hexdigest())
        # The old sequence with new bytes is neither complete transaction state.

    def test_early_clear_can_destroy_irreversible_commit(self):
        self.prepare()
        self.store.write(512*8,self.commit);self.store.flush()
        self.store.write(19*4096,self.after)
        self.store.write(32*4096,self.data)
        self.store.write(512*8,bytes(512))
        clear_version=self.store.pending[-1][0]
        sequence,digest=self.inspect(versions=[clear_version])
        self.assertEqual(sequence,0)
        self.assertEqual(digest,fsck.hashlib.sha256(b'old').hexdigest())
        # TX-C was stable; losing that committed update violates the protocol.

    def test_reuse_payload_while_prior_commit_is_durable_refuses_recovery(self):
        self.prepare()
        self.store.write(512*8,self.commit);self.store.flush()
        self.store.write(4*4096,b'two'+bytes(4093))
        with self.assertRaises(fsck.Corruption):
            self.inspect(policy='all')


if __name__=='__main__':
    unittest.main()

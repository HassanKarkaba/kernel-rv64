import importlib.util
from pathlib import Path
import socket
import struct
import threading
import unittest

SPEC = importlib.util.spec_from_file_location('nbd_fault',Path(__file__).resolve().parents[1]/'tools'/'nbd_fault.py')
nbd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nbd)


class PersistenceModel(unittest.TestCase):
    def test_completed_flush_cannot_be_rolled_back(self):
        store=nbd.SectorStore(bytes(nbd.SIZE))
        store.write(0,b'a'*512)
        self.assertEqual(store.read(0,512),b'a'*512)
        self.assertEqual(store.outcome('none')[0][:512],bytes(512))
        store.flush()
        store.write(0,b'b'*512)
        store.write(0,b'c'*512)
        ids=[v for v,_,_ in store.pending]
        self.assertEqual(store.outcome('none')[0][:512],b'a'*512)
        self.assertEqual(store.outcome(versions=[ids[0]])[0][:512],b'b'*512)
        self.assertEqual(store.outcome(versions=ids)[0][:512],b'c'*512)
        with self.assertRaises(ValueError):
            store.outcome(versions=[1])

    def test_power_cut_is_at_exact_sector_event(self):
        store=nbd.SectorStore(bytes(nbd.SIZE),nbd.Trace(cut=3))
        with self.assertRaises(nbd.PowerCut):
            store.write(0,b'x'*4096)
        self.assertEqual(len(store.pending),4)
        image,selected=store.outcome('all')
        self.assertEqual(selected,[1,2,3,4])
        self.assertEqual(image[:2048],b'x'*2048)
        self.assertEqual(image[2048:4096],bytes(2048))

    def test_exhaustive_declared_subspaces(self):
        small=[(i+1,i,bytes(512)) for i in range(12)]
        outcomes=list(nbd.exhaustive_small_versions(small))
        self.assertEqual(len(outcomes),4096)
        self.assertEqual(len(set(outcomes)),4096)
        pending=[(i+1,i,bytes(512)) for i in range(16)]
        outcomes=set(nbd.exhaustive_small_versions(pending))
        for mask in range(256):
            selection=tuple(i+1 for i in range(8) if mask&(1<<i))
            self.assertIn(selection,outcomes)
            self.assertIn(selection+tuple(range(9,17)),outcomes)
        with self.assertRaises(ValueError):
            list(nbd.exhaustive_small_versions([(1,0,b''),(2,0,b'')]))

    def test_reject_unaligned_and_oversized_io(self):
        store=nbd.SectorStore(bytes(nbd.SIZE))
        for offset,length in [(1,512),(0,1),(nbd.SIZE,512),(0,nbd.MAX_REQUEST+512)]:
            with self.assertRaises(ValueError):
                store.read(offset,length)


class Protocol(unittest.TestCase):
    def setUp(self):
        self.store=nbd.SectorStore(bytes(nbd.SIZE))
        self.server,self.client=socket.socketpair()
        self.client.settimeout(5)
        self.errors=[]
        def run():
            try:
                with self.server:
                    nbd.session(self.server,self.store)
            except Exception as error:
                self.errors.append(error)
        self.thread=threading.Thread(target=run,daemon=True)
        self.thread.start()
        self.assertEqual(struct.unpack('>QQH',nbd.receive(self.client,18)),(nbd.MAGIC,nbd.OPTIONS_MAGIC,3))
        self.client.sendall(struct.pack('>I',3))

    def tearDown(self):
        self.client.close()
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())

    def option(self,number,data=b''):
        self.client.sendall(struct.pack('>QII',nbd.OPTIONS_MAGIC,number,len(data))+data)

    def option_reply(self):
        magic,option,kind,length=struct.unpack('>QIII',nbd.receive(self.client,20))
        self.assertEqual(magic,nbd.OPTION_REPLY_MAGIC)
        return option,kind,nbd.receive(self.client,length)

    def enter(self):
        self.option(8)  # Structured replies deliberately unsupported.
        self.assertEqual(self.option_reply()[:2],(8,0x80000001))
        self.option(7,struct.pack('>IHH',0,1,3))
        self.assertEqual(self.option_reply(),(7,3,struct.pack('>HQH',0,nbd.SIZE,5)))
        self.assertEqual(self.option_reply(),(7,3,struct.pack('>HIII',3,512,4096,nbd.MAX_REQUEST)))
        self.assertEqual(self.option_reply(),(7,1,b''))

    def request(self,command,offset=0,length=0,data=b'',flags=0):
        self.client.sendall(struct.pack('>IHHQQI',nbd.REQUEST_MAGIC,flags,command,123,offset,length)+data)
        if command==2:
            return None
        magic,error,handle=struct.unpack('>IIQ',nbd.receive(self.client,16))
        self.assertEqual((magic,handle),(nbd.REPLY_MAGIC,123))
        content=nbd.receive(self.client,length) if command==0 and error==0 else b''
        return error,content

    def test_write_read_flush_and_unsupported_operations(self):
        self.enter()
        self.assertEqual(self.request(1,length=512,data=b'z'*512),(0,b''))
        self.assertEqual(self.request(0,length=512),(0,b'z'*512))
        self.assertEqual(self.store.stable[:512],bytes(512))
        self.assertEqual(self.request(3),(0,b''))
        self.assertEqual(self.store.stable[:512],b'z'*512)
        self.assertEqual(self.request(6,length=512)[0],22)
        self.assertEqual(self.request(1,length=512,data=b'q'*512,flags=1)[0],22)
        self.assertEqual(self.request(0,length=512),(0,b'z'*512))
        self.request(2)
        self.thread.join(5)
        self.assertFalse(self.errors)

    def test_injected_backend_error_is_a_protocol_error_reply(self):
        self.enter()
        def fail(offset,length):
            raise nbd.CommandError(5)
        self.store.read=fail
        self.assertEqual(self.request(0,length=512),(5,b''))
        self.request(2)
        self.thread.join(5)
        self.assertFalse(self.errors)

    def test_export_name_fallback(self):
        self.option(1,b'kfs')
        self.assertEqual(struct.unpack('>QH',nbd.receive(self.client,10)),(nbd.SIZE,5))
        self.request(2)
        self.thread.join(5)
        self.assertFalse(self.errors)


if __name__=='__main__':
    unittest.main()

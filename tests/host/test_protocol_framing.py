from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from protocol import trusted_records
from guest_test import validate_records

class CompleteTrustedFraming(unittest.TestCase):
    def test_complete_json_without_final_delimiter_is_not_a_record(self):
        for data in (b'KTEST {"event":"result","result":"PASS"}',b'KTEST {"event":"result","result":"PASS"}\r'):
            with self.assertRaisesRegex(ValueError,'unterminated'):
                trusted_records(data)

    def test_lf_crlf_escaped_output_and_unrelated_tail(self):
        data=b'UOUT {"data":"KTEST {\\"result\\":\\"PASS\\"}\\n"}\nKTEST {"n":1}\r\nKTEST {"n":2}\n> '
        self.assertEqual(trusted_records(data),[{'n':1},{'n':2}])

    def test_ambiguous_json_and_unbounded_record_rejected(self):
        for payload in (b'{"a":1,"a":2}',b'{"a":NaN}',b'[]',b'{"data":"'+b'x'*513+b'"}'):
            with self.assertRaises(ValueError):trusted_records(b'KTEST '+payload+b'\n')

    def test_guest_supervisor_cannot_pass_on_undelimited_terminal(self):
        import json
        common={'schema':1,'run_id':'a'*32,'boot_id':'b'*32,'case_id':'guest-selftest'}
        first={**common,'event':'start','sequence':1}
        terminal={**common,'event':'result','sequence':2,'result':'PASS','child_kind':0,'child_code':0}
        data=b'KTEST '+json.dumps(first).encode()+b'\nKTEST '+json.dumps(terminal).encode()
        with self.assertRaisesRegex(ValueError,'unterminated'):validate_records(data,'a'*32,'b'*32)
        self.assertEqual(len(validate_records(data+b'\n','a'*32,'b'*32)),2)

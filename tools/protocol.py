"""Parse only complete kernel-owned KTEST lines; user output is never authority."""
import json


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate trusted record key')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('nonfinite trusted record number')


def trusted_records(serial):
    lines = serial.split(b'\n')
    if lines[-1].startswith(b'KTEST '):
        raise ValueError('unterminated trusted KTEST record')
    records = []
    for line in lines[:-1]:
        if not line.startswith(b'KTEST '):
            continue
        payload = line[6:].removesuffix(b'\r')
        if len(payload) > 512:
            raise ValueError('trusted KTEST record exceeds kernel bound')
        record = json.loads(payload, object_pairs_hook=_object, parse_constant=_constant)
        if not isinstance(record, dict):
            raise ValueError('KTEST record is not an object')
        records.append(record)
    return records

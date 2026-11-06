import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from trace_test import analyze


def valid_rows():
    events=[(1,258,0),(2,258,0),(5,258,0)]
    for reason in [6,0x100,4]:
        events += [(3,258,reason),(4,258,reason),(1,258,0),(2,258,0)]
    events += [(7,1,4),(8,1,1),(9,1,0),(6,258,0)]
    events += [(kind,1,0) for kind in range(100,110)]
    return [dict(event="trace",ordinal=i,ticks=i,kind=k,object=o,detail=d) for i,(k,o,d) in enumerate(events,1)]


def test_complete_trace():
    analyze(valid_rows())


def test_duplicate_ready():
    rows=valid_rows();rows[1]["kind"]=1
    with pytest.raises(ValueError,match="duplicate READY"):analyze(rows)


def test_unregistered_wakeup():
    rows=valid_rows();rows[4]["detail"]=99
    with pytest.raises(ValueError,match="registered waiter"):analyze(rows)


def test_completion_ownership():
    rows=valid_rows();next(r for r in rows if r["kind"]==8)["object"]=99
    with pytest.raises(ValueError,match="matching submission"):analyze(rows)


def test_missing_durable_phase():
    rows=valid_rows();next(r for r in rows if r["kind"]==105)["kind"]=104
    with pytest.raises(ValueError,match="journal phase"):analyze(rows)

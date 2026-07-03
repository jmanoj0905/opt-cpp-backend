# Unit tests for step_limits. Run under Python 3: python3 test_step_limits.py
# (step_limits itself is Python 2/3 compatible so vg_to_opt_trace.py can import
# it in-container under Python 2.)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from step_limits import apply_step_limits, fingerprint


def pt(line, locals_=None, glob=None, heap=None, stdout="", event="step_line"):
    return {
        "line": line,
        "event": event,
        "stdout": stdout,
        "stack_to_render": [
            {"frame_id": "0xFF", "encoded_locals": locals_ or {}}
        ],
        "globals": glob or {},
        "heap": heap or {},
    }


def test_empty_list_returned_as_is():
    assert apply_step_limits([], False) == []


def test_terminating_trace_is_unchanged():
    pts = [pt(1, {"i": 0}), pt(2, {"i": 1})]
    pts[-1]["event"] = "return"
    out = apply_step_limits(pts, False)
    assert len(out) == 2
    assert out[-1]["event"] == "return"
    assert out[-1].get("exception_msg", "") == ""


def test_state_cycle_flagged_as_infinite_loop():
    # index 0 and index 2 are byte-identical -> first repeat at index 2
    pts = [pt(5, {"x": 1}), pt(6, {"x": 2}), pt(5, {"x": 1})]
    out = apply_step_limits(pts, True)  # budget exhausted + cycle
    assert len(out) == 3
    assert out[-1]["event"] == "infinite_loop_detected"
    assert "infinite loop" in out[-1]["exception_msg"]
    assert "5" in out[-1]["exception_msg"]


def test_stdout_excluded_from_fingerprint():
    # identical memory, different stdout -> still a repeat (needs budget exhausted to flag)
    pts = [pt(5, {"x": 1}, stdout="a"), pt(5, {"x": 1}, stdout="ab")]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "infinite_loop_detected"


def test_state_repeat_not_flagged_when_terminated_within_budget():
    # identical observable state at index 0 and 2, but program returned on
    # its own (budget NOT exhausted) -> must NOT be called an infinite loop
    pts = [pt(5, {"x": 1}), pt(6, {"x": 2}), pt(5, {"x": 1})]
    pts[-1]["event"] = "return"
    out = apply_step_limits(pts, False)
    assert len(out) == 3
    assert out[-1]["event"] == "return"
    assert out[-1].get("exception_msg", "") == ""


def test_same_cycle_flagged_only_when_budget_exhausted():
    def cyc():
        return [pt(5, {"x": 1}), pt(6, {"x": 2}), pt(5, {"x": 1})]
    assert apply_step_limits(cyc(), False)[-1]["event"] != "infinite_loop_detected"
    assert apply_step_limits(cyc(), True)[-1]["event"] == "infinite_loop_detected"


def test_long_not_stuck_gets_budget_message():
    pts = [pt(1, {"i": 0}), pt(1, {"i": 1}), pt(1, {"i": 2})]  # distinct states
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "instruction_limit_reached"
    assert "smaller input" in out[-1]["exception_msg"]


def test_display_ceiling_truncates():
    pts = [pt(1, {"i": n}) for n in range(10)]  # 10 distinct states
    out = apply_step_limits(pts, False, display_cap=5)
    assert len(out) == 5
    assert out[-1]["event"] == "instruction_limit_reached"
    assert "smaller input" in out[-1]["exception_msg"]


def test_no_false_positive_on_distinct_states():
    pts = [pt(1, {"i": n}) for n in range(5)]
    pts[-1]["event"] = "return"
    out = apply_step_limits(pts, False)
    assert len(out) == 5
    assert out[-1]["event"] == "return"


def test_fingerprint_differs_on_line_and_matches_on_state():
    assert fingerprint(pt(1, {"i": 0})) == fingerprint(pt(1, {"i": 0}, stdout="z"))
    assert fingerprint(pt(1, {"i": 0})) != fingerprint(pt(2, {"i": 0}))
    assert fingerprint(pt(1, {"i": 0})) != fingerprint(pt(1, {"i": 1}))


if __name__ == "__main__":
    tests = sorted(
        (k, v) for k, v in globals().items()
        if k.startswith("test_") and callable(v)
    )
    for name, fn in tests:
        fn()
        print("ok " + name)
    print("ALL PASS (%d tests)" % len(tests))

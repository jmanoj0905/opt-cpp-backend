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
    # stdout differs but is excluded from the fingerprint, so the final state
    # still matches an earlier one; pt6 is a real loop body between the two
    # sightings -> genuine cycle.
    pts = [pt(5, {"x": 1}, stdout="a"), pt(6, {"x": 2}), pt(5, {"x": 1}, stdout="abc")]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "infinite_loop_detected"


def test_adjacent_duplicate_final_state_is_not_a_loop():
    # The surround-regions DFS bug: a multi-part `if` line traces as several
    # basic blocks with no observable change; cut off at the step cap on the
    # SECOND such block, the final state equals its immediate predecessor
    # (empty loop body). That is not a cycle -- it is too long.
    pts = [pt(1, {"i": 0}), pt(2, {"i": 1}), pt(6, {"i": 2}), pt(6, {"i": 2})]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "instruction_limit_reached"
    assert "smaller input" in out[-1]["exception_msg"]


def test_short_run_duplicate_final_state_is_not_a_loop():
    # A 3-long identical tail run, program otherwise progressing, no earlier
    # sighting of the repeated state -> below the spin threshold -> too long.
    pts = [pt(1, {"i": 0}), pt(2, {"i": 1}),
           pt(9, {"s": 0}), pt(9, {"s": 0}), pt(9, {"s": 0})]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "instruction_limit_reached"


def test_single_line_spin_flagged_as_infinite_loop():
    # while(true); -- a long run of byte-identical consecutive states at the
    # step cap. No distinct body, but the run length proves the spin.
    pts = [pt(1, {"i": 0}), pt(2, {"i": 1})]
    pts += [pt(9, {"s": 0}) for _ in range(9)]  # >= SPIN_RUN identical
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


def test_cycle_beyond_display_cap_is_instruction_limit():
    # first state repeat is BEYOND display_cap -> not shown as a loop; the
    # displayed window has no cycle, so it is labeled too-long at the ceiling
    pts = [pt(n, {"i": n}) for n in range(6)]      # 6 distinct states
    pts.append(pt(0, {"i": 0}))                    # repeat of index 0, at index 6
    out = apply_step_limits(pts, True, display_cap=5)
    assert len(out) == 5
    assert out[-1]["event"] == "instruction_limit_reached"
    assert "smaller input" in out[-1]["exception_msg"]


def test_early_call_then_step_line_repeat_is_not_a_loop():
    # A `call` event and the same-line body `step_line` share an identical
    # fingerprint (event is excluded from the fingerprint), so they look like a
    # repeat -- but entering a function and running its first line is NOT a
    # cycle. The program is merely too long: its FINAL captured state is novel.
    # Regression: this used to trim at the coincidental repeat (index 1) and
    # mislabel a correct, terminating program as an infinite loop.
    pts = [
        pt(12, {"x": 1}, event="call"),       # enter TreeNode::TreeNode
        pt(12, {"x": 1}, event="step_line"),  # its body, identical fingerprint
        pt(13, {"x": 2}),
        pt(14, {"x": 3}),
        pt(20, {"x": 4}),                     # novel final state -> still running
    ]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "instruction_limit_reached"
    assert "smaller input" in out[-1]["exception_msg"]
    assert len(out) == 5


def test_mid_trace_state_repeat_is_not_a_loop_when_final_state_novel():
    # A loop header revisited after per-iteration work whose heap allocations
    # are unreachable (leaked) at the sampling instant produces two identical
    # observable states mid-trace. That is not a cycle; the program moves on and
    # is cut off at a fresh state. Must be too-long, not an infinite loop.
    pts = [
        pt(88, {"t": 0}),   # loop header, iteration 1
        pt(15, {"t": 0}),
        pt(88, {"t": 0}),   # loop header again -- identical to index 0
        pt(16, {"t": 1}),
        pt(17, {"t": 2}),   # novel final state
    ]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "instruction_limit_reached"
    assert len(out) == 5


def test_infinite_loop_flagged_when_final_state_recurs():
    # A genuine loop is cut off INSIDE its cycle, so the final captured state
    # has been seen before. Preamble then two iterations of an (A, B) cycle.
    pts = [
        pt(1, {"i": 0}),                    # preamble
        pt(5, {"x": 0}), pt(6, {"x": 0}),   # iteration 1
        pt(5, {"x": 0}), pt(6, {"x": 0}),   # iteration 2 -> final state recurs
    ]
    out = apply_step_limits(pts, True)
    assert out[-1]["event"] == "infinite_loop_detected"
    assert "6" in out[-1]["exception_msg"]


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

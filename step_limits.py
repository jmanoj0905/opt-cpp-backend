# cpp-tutor: intelligent step-cap logic for OPT trace postprocessing.
#
# Decides how a trace ends: a program that terminates within all resource
# limits is left untouched; a true infinite loop (when the program has
# exhausted its raw-instruction budget AND returns to a byte-identical
# observable state -- in the deterministic tracer sandbox, no net, no stdin,
# no clock branching -- this proves non-termination) is trimmed at the first
# repeat and labeled; a program merely too long (raw-instruction cap hit, no
# state repeat) is labeled as such.
#
# Python 2/3 compatible on purpose: imported by vg_to_opt_trace.py under
# Python 2 in-container, unit-tested under Python 3. ASCII only. No Python-3-only
# syntax, no print statements.
import json

DISPLAY_CAP = 2000

# Minimum length of an identical (line, frame) run at the tail of the RAW
# pre-dedup trace that marks a genuine single-line spin loop (while(true);).
# Used by vg_to_opt_trace.py, which sees the raw stream; the deduped stream
# step_limits receives has already collapsed such a run away.
SPIN_RUN = 8

# Byte/wall budgets that keep the whole tracing pipeline inside the backend's
# 120s request timeout even when each step's memory dump is huge (a big
# std::vector mutated in a long loop writes ~50KB per record; 3500 records is
# a 100MB+ vgtrace that thrashes and then OOMs the 256MB container). The raw
# MAX_STEPS cap in mc_translate.c bounds record COUNT only, so record SIZE
# needs its own cap:
#  - VGTRACE_BYTE_BUDGET stops the valgrind stage (run_cpp_backend.py
#    watchdog) and the postprocess parse loop (vg_to_opt_trace.py) once the
#    vgtrace outgrows what the postprocessor can decode inside its RAM/time
#    slice. Measured on arm64/OrbStack: valgrind writes ~3.6MB/s, postprocess
#    parses ~10MB/s, so 128MB is ~36s + ~13s locally; production is ~7.6x slower
#    but then the wall cap below binds first.
#  - VALGRIND_WALL_SECONDS kills a valgrind run that burns wall clock without
#    growing the trace (heavy compute between traced lines). Sized so
#    wall + worst-case parse of what could be written in that wall time +
#    compile stays under the 120s backend timeout at production speeds.
# Either cutoff yields a TRUNCATED trace that step_limits labels for the
# learner instead of the request dying as a bare 503 with zero steps.
# Sized from a measured reference (5x5 surround-regions DFS): 24,043 raw
# steps, 90.8 MB vgtrace, 46.6 s local wall.
VGTRACE_BYTE_BUDGET = 128 * 1024 * 1024
VALGRIND_WALL_SECONDS = 90

_TOO_LONG_MSG = ("This program runs longer than we can trace. Trace these "
                 "steps, then try a smaller input to see the rest.")


def _loop_msg(line):
    return ("This looks like an infinite loop -- the program keeps returning "
            "to the same state around line %d. Check your loop condition."
            % line)


def fingerprint(point):
    """Stable string identity of a point's observable program state.

    Two points with identical fingerprints are in identical states; in the
    deterministic sandbox that means the program must repeat forever. Excludes
    stdout/event/func_name (not part of memory state; func_name is derivable
    from the stack)."""
    frames = []
    for f in point.get("stack_to_render", []):
        frames.append([f.get("frame_id"), f.get("encoded_locals", {})])
    state = [point.get("line"), frames,
             point.get("globals", {}), point.get("heap", {})]
    return json.dumps(state, sort_keys=True)


def _loop_cut_index(points):
    """Index to trim at for a genuine infinite loop, or None.

    Called only when the program was cut off by the step budget, i.e. it did
    NOT terminate on its own. Two possibilities:

      * It loops forever -> it was cut off INSIDE its cycle, so the final
        captured state has occurred before in the trace.
      * It was merely slow -> it was cut off while still making progress, at a
        state it has not been in before.

    So we key the decision on the FINAL captured state, not on the first repeat
    anywhere. An early, coincidental fingerprint match is NOT a cycle and must
    not truncate the trace:

      * a `call` event and the same-line body `step_line` share a fingerprint
        (the fingerprint excludes `event`), yet entering a function and running
        its first line is not a loop; and
      * a loop header revisited after per-iteration work whose heap allocations
        are unreachable at the sampling instant (e.g. a leaked structure whose
        only pointer is a not-yet-assigned local) repeats an observable state
        while the program is in fact progressing.

    Both are common in ordinary terminating programs (test-case loops, tree
    builders) and both used to trip a first-repeat scan. Keying on the final
    state ignores them: the program moves on to fresh states and is cut off at
    one of them.

    Returns a slice length: keep the trace through the SECOND occurrence of the
    final state, so the learner sees the loop reach the same state twice (one
    full period) and then stops -- short for a long loop, whole for a tiny one.
    Returns None when the final state is novel (no cycle).

    Guards against non-trivial-period false positives too: a degenerate repeat
    with an empty body between the two sightings (e.g. two basic-block samples
    of one multi-part source line caught at the step cap) is NOT a cycle.
    (Single-line spins are handled separately, upstream, via the spin flag.)"""
    n = len(points)
    if n < 2:
        return None
    fps = [fingerprint(p) for p in points]
    last = fps[-1]
    first = None
    for i in range(n):
        if fps[i] != last:
            continue
        if first is None:
            first = i
            continue
        # Second occurrence at i: the pair (first, i) is the cut boundary.
        # Only a real cycle counts: it did observable work between the two
        # sightings (a distinct intermediate state -> real loop body). A
        # degenerate repeat -- adjacent sightings with an empty body, e.g. two
        # basic-block samples of one multi-part source line cut off at the
        # step cap -- is NOT a loop; the program was still progressing.
        has_body = any(fps[k] != last for k in range(first + 1, i))
        if has_body:
            return i + 1
        return None
    return None


def apply_step_limits(points, max_steps_exceeded, spin_at_cap=False,
                       display_cap=DISPLAY_CAP):
    """Trim `points` and tag the final point with an end-of-trace reason.

    Budget-gated: infinite-loop classification happens ONLY when the program
    exhausted the raw-instruction budget (max_steps_exceeded). A program that
    terminates within budget is never flagged as looping -- an exact repeat of
    its observable state does not prove non-termination, because the fingerprint
    cannot see STL-internal heap/iterator state that may still be progressing.
    `spin_at_cap` (set by vg_to_opt_trace.py from the raw pre-dedup tail) marks
    a single-line spin the dedup pass has already collapsed; it is labeled an
    infinite loop directly. Never mutates the caller's input dicts."""
    if not points:
        return points

    if max_steps_exceeded:
        # Program exhausted the raw budget -- it did NOT terminate on its own.
        # Decide loop vs. too-long from the final captured state (see
        # _loop_cut_index). Work within the display window so a decision made on
        # the final shown state matches what the learner sees.
        window = points[:display_cap] if len(points) > display_cap else points
        if spin_at_cap:
            # Single-line spin (while(true);): the raw cap was hit while stuck
            # on one (line, frame). ONLY_ONE_REC_PER_LINE dedup already
            # collapsed the run, so the deduped window cannot show the cycle;
            # vg_to_opt_trace.py set this flag from the raw tail. Label directly.
            spun = window[:]
            spun[-1] = dict(spun[-1])
            spun[-1]["event"] = "infinite_loop_detected"
            spun[-1]["exception_msg"] = _loop_msg(spun[-1]["line"])
            return spun
        cut = _loop_cut_index(window)
        if cut is not None:
            trimmed = window[:cut]
            trimmed[-1] = dict(trimmed[-1])
            trimmed[-1]["event"] = "infinite_loop_detected"
            trimmed[-1]["exception_msg"] = _loop_msg(trimmed[-1]["line"])
            return trimmed
        window = window[:]
        window[-1] = dict(window[-1])
        window[-1]["event"] = "instruction_limit_reached"
        window[-1]["exception_msg"] = _TOO_LONG_MSG
        return window

    # Program terminated within budget -> not an infinite loop. Only guard the
    # display ceiling.
    if len(points) > display_cap:
        points = points[:display_cap]
        points[-1] = dict(points[-1])
        points[-1]["event"] = "instruction_limit_reached"
        points[-1]["exception_msg"] = _TOO_LONG_MSG
    return points

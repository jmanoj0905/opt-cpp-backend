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


def apply_step_limits(points, max_steps_exceeded, display_cap=DISPLAY_CAP):
    """Trim `points` and tag the final point with an end-of-trace reason.

    Budget-gated: infinite-loop classification happens ONLY when the program
    exhausted the raw-instruction budget (max_steps_exceeded). A program that
    terminates within budget is never flagged as looping -- an exact repeat of
    its observable state does not prove non-termination, because the fingerprint
    cannot see STL-internal heap/iterator state that may still be progressing.
    Never mutates the caller's input dicts."""
    if not points:
        return points

    # Accepted residual: a terminating-but-very-long program that BOTH exhausts
    # the budget AND happens to repeat an observable state (possible because the
    # fingerprint cannot see STL-internal heap/iterator state) is labeled
    # infinite_loop_detected rather than instruction_limit_reached. Both outcomes
    # stop the trace gracefully; the mislabel is cosmetic and only on programs
    # already too long to finish.
    if max_steps_exceeded:
        # Program exhausted the raw budget -- it did NOT terminate on its own.
        # An exact observable-state repeat now proves a non-progressing cycle
        # (a terminating program would have finished before the budget ran out
        # and never reached this branch). No repeat -> merely too long.
        seen = set()
        for i, point in enumerate(points):
            if i >= display_cap:
                break  # a cycle beyond the display ceiling is not shown;
                       # fall through to the too-long path below
            fp = fingerprint(point)
            if fp in seen:
                trimmed = points[:i + 1]
                trimmed[-1] = dict(trimmed[-1])
                trimmed[-1]["event"] = "infinite_loop_detected"
                trimmed[-1]["exception_msg"] = _loop_msg(trimmed[-1]["line"])
                return trimmed
            seen.add(fp)
        if len(points) > display_cap:
            points = points[:display_cap]
        else:
            points = points[:]
        points[-1] = dict(points[-1])
        points[-1]["event"] = "instruction_limit_reached"
        points[-1]["exception_msg"] = _TOO_LONG_MSG
        return points

    # Program terminated within budget -> not an infinite loop. Only guard the
    # display ceiling.
    if len(points) > display_cap:
        points = points[:display_cap]
        points[-1] = dict(points[-1])
        points[-1]["event"] = "instruction_limit_reached"
        points[-1]["exception_msg"] = _TOO_LONG_MSG
    return points

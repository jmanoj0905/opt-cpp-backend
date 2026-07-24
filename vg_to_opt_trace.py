# Convert a raw trace created by the Valgrind OPT C backend to a format
# that the OPT frontend can digest, making various optimizations and
# clean-ups along the way to beautify the trace

# Created 2015-10-04 by Philip Guo

# pass in full path name of a source file, which should end in '.c' or '.cpp'.
# assumes that the Valgrind-produced trace is $basename.vgtrace
# (without the '.c.' or '.cpp' extension)
#
# optionally, if you want to pass an error message to display at the end
# of the trace, pass it in via the --end-of-trace-error-msg argument


# this is pretty brittle and dependent on the user's gcc version and
# such because it generates code to conform to certain calling
# conventions, frame pointer settings (DON'T omit it!), etc., eeek
#
# we're assuming that the user has compiled with:
# gcc -ggdb -O0 -fno-omit-frame-pointer
#
# on a platform like:
'''
$ gcc -v
Using built-in specs.
COLLECT_GCC=gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/4.8/lto-wrapper
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Ubuntu 4.8.4-2ubuntu1~14.04' --with-bugurl=file:///usr/share/doc/gcc-4.8/README.Bugs --enable-languages=c,c++,java,go,d,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-4.8 --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --with-gxx-include-dir=/usr/include/c++/4.8 --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --enable-gnu-unique-object --disable-libmudflap --enable-plugin --with-system-zlib --disable-browser-plugin --enable-java-awt=gtk --enable-gtk-cairo --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-4.8-amd64/jre --enable-java-home --with-jvm-root-dir=/usr/lib/jvm/java-1.5.0-gcj-4.8-amd64 --with-jvm-jar-dir=/usr/lib/jvm-exports/java-1.5.0-gcj-4.8-amd64 --with-arch-directory=amd64 --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --enable-objc-gc --enable-multiarch --disable-werror --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
Thread model: posix
gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04)
'''


import json
import os
import pprint
import re
import sys
from optparse import OptionParser
from step_limits import apply_step_limits, VGTRACE_BYTE_BUDGET, SPIN_RUN

pp = pprint.PrettyPrinter(indent=2)

RECORD_SEP = '=== pg_trace_inst ==='


ONLY_ONE_REC_PER_LINE = True

all_execution_points = []

# cpp-tutor: set True when the raw-instruction cap fires in mc_translate.c
# (the MAX_STEPS_EXCEEDED marker). Lets postprocess tell "program too long"
# apart from natural termination. See step_limits.apply_step_limits.
max_steps_exceeded = False

# False if record isn't parsed properly or is an exception
def process_record(lines):
    global max_steps_exceeded
    if not lines:
        return True # 'nil success case to keep the parser going

    err_lines = []
    stdout_lines = []
    regular_lines = []
    for e in lines:
        if e.startswith('ERROR: '):
            err_lines.append(e)
        elif e.startswith('STDOUT: '):
            stdout_lines.append(e)
        elif e.startswith('MAX_STEPS_EXCEEDED'):
            max_steps_exceeded = True
        else:
            regular_lines.append(e)

    rec = '\n'.join(regular_lines)
    try:
        # sometimes floating-point values print as:
        # "val":******
        # when they're weird values like overflow and NaN. in those
        # cases, replace with "val": null so as not to crash the json
        # parser
        rec = rec.replace('"val":******', '"val":null')
        obj = json.loads(rec)
    except ValueError:
        print >> sys.stderr, "Ugh, bad record!", rec
        return False

    # normally exactly one STDOUT line per record; a record cut off mid-write
    # (the run_cpp_backend.py watchdog kills valgrind when the trace outgrows
    # its budget) can be missing it -- drop the record instead of crashing
    if len(stdout_lines) != 1:
        return False
    # it's encoded as JSON in a single line
    stdout_str = json.loads(stdout_lines[0][len('STDOUT: '):])

    # take the first error only
    err_str = err_lines[0] if err_lines else None

    x = process_json_obj(obj, err_str, stdout_str)
    all_execution_points.append(x)
    # it's a good idea to fail-fast on first exception since it's
    # pedagogically bad to keep executing despite errors
    if x['event'] == 'exception':
        return False
    return True


def process_json_obj(obj, err_str, stdout_str):
    #print '---'
    #pp.pprint(obj)
    #print

    assert len(obj['stack']) > 0 # C programs always have a main at least!
    obj['stack'].reverse() # make the stack grow down to follow convention
    top_stack_entry = obj['stack'][-1]

    # create an execution point object
    ret = {}

    heap = {}
    stack = []
    enc_globals = {}
    ret['heap'] = heap
    ret['stack_to_render'] = stack
    ret['globals'] = enc_globals

    # sometimes there are no globals in a trace
    if 'ordered_globals' in obj:
        ret['ordered_globals'] = obj['ordered_globals']
    else:
        ret['ordered_globals'] = []

    ret['line'] = obj['line']
    ret['func_name'] = top_stack_entry['func_name'] # use the 'topmost' entry's name
    # cpp-tutor: raw return-value register (RAX/X0), captured on every
    # instruction by mc_translate.c. Only meaningful on the last instruction
    # of a frame that's about to pop -- see attach_return_values() below.
    ret['ret_reg'] = obj.get('ret_reg')

    if err_str:
        ret['event'] = 'exception'
        ret['exception_msg'] = err_str + '\n(Stopped running after the first error. Please fix your code.)'
    else:
        ret['event'] = 'step_line'

    ret['stdout'] = stdout_str

    if 'globals' in obj:
        for g_var, g_val in obj['globals'].iteritems():
            enc_globals[g_var] = encode_value(g_val, heap)

    for depth, e in enumerate(obj['stack']):
        stack_obj = {}
        stack.append(stack_obj)

        stack_obj['func_name'] = e['func_name']
        stack_obj['ordered_varnames'] = e['ordered_varnames']
        stack_obj['is_highlighted'] = e is top_stack_entry

        # FP alone is not a unique frame ID: g++-compiled member functions
        # (methods, constructors) report the *caller's* FP for their entire
        # lifetime, so a method frame and its parent share an FP. Suffix the
        # stack depth to disambiguate; depth is stable for a live frame, so
        # the ID stays stable across steps and call/return detection (which
        # compares whole frame_id lists) keeps working.
        stack_obj['frame_id'] = e['FP'] + '_' + str(depth)

        stack_obj['unique_hash'] = stack_obj['func_name'] + '_' + stack_obj['frame_id']

        if 'line' in e:
            stack_obj['line'] = e['line']

        # unsupported
        stack_obj['is_parent'] = False
        stack_obj['is_zombie'] = False
        stack_obj['parent_frame_id_list'] = []

        enc_locals = {}
        stack_obj['encoded_locals'] = enc_locals

        for local_var, local_val in e['locals'].iteritems():
            enc_locals[local_var] = encode_value(local_val, heap)


    #pp.pprint(ret)
    #print [(e['func_name'], e['frame_id']) for e in ret['stack_to_render']]

    return ret


# returns an encoded value in OPT format and possibly mutates the heap
def encode_value(obj, heap):
    if obj['kind'] == 'base':
        return ['C_DATA', obj['addr'], obj['type'], obj['val']]

    elif obj['kind'] == 'pointer':
        if 'deref_val' in obj:
            encode_value(obj['deref_val'], heap) # update the heap
        return ['C_DATA', obj['addr'], 'pointer', obj['val']]

    elif obj['kind'] == 'struct':
        ret = ['C_STRUCT', obj['addr'], obj['type']]

        # sort struct members by address so that they look ORDERED
        members = obj['val'].items()
        members.sort(key=lambda e: e[1]['addr'])
        for k, v in members:
            entry = [k, encode_value(v, heap)] # TODO: is an infinite loop possible here?
            ret.append(entry)
        return ret

    elif obj['kind'] == 'array':
        # backwards compatibility for old 1-D array format:
        if 'dimensions' not in obj or len(obj['dimensions']) < 2:
            ret = ['C_ARRAY', obj['addr']]
            for e in obj['val']:
                ret.append(encode_value(e, heap)) # TODO: is an infinite loop possible here?
            return ret
        else:
            # put dimensions as the 3rd element:
            ret = ['C_MULTIDIMENSIONAL_ARRAY', obj['addr'], obj['dimensions']]
            for e in obj['val']:
                ret.append(encode_value(e, heap)) # TODO: is an infinite loop possible here?
            return ret

    elif obj['kind'] == 'typedef':
        # pass on the typedef type name into obj['val'], then recurse
        obj['val']['type'] = obj['type']
        return encode_value(obj['val'], heap)

    elif obj['kind'] == 'heap_block':
        assert obj['addr'] not in heap
        new_elt = ['C_ARRAY', obj['addr']]
        for e in obj['val']:
            new_elt.append(encode_value(e, heap)) # TODO: is an infinite loop possible here?
        heap[obj['addr']] = new_elt
        # TODO: what about heap-to-heap pointers?

    else:
        assert False


# cpp-tutor: return-value capture (scalar-only MVP -- see mc_translate.c's
# PG_RETVAL_REG_OFFSET comment). We have no DWARF return-type info, so we
# can't tell a void function from an int-returning one by type; instead we
# check whether the frame, at any point during ITS OWN invocation, executed
# a source line containing "return <expr>;" -- if so we trust ret_reg
# (RAX/X0), read on the frame's last traced instruction, to hold the actual
# return value (the epilogue that follows never clobbers it).
# search() (not match()/^-anchored) on purpose: a base case like
# "if (n <= 1) return n;" puts the return statement mid-line.
RETURN_EXPR_RE = re.compile(r'\breturn\b\s*([^;]*);')


def frame_returns_scalar(lines_visited):
    for ln in lines_visited:
        if ln is None or ln < 1 or ln > len(source_lines):
            continue
        m = RETURN_EXPR_RE.search(source_lines[ln - 1])
        if m and m.group(1).strip():
            return True
    return False


def to_signed32(u):
    u &= 0xFFFFFFFF
    return u - 0x100000000 if u & 0x80000000 else u


def attach_return_values(execution_points):
    for i, pt in enumerate(execution_points):
        if pt['event'] != 'return':
            continue
        frames = pt['stack_to_render']
        ret_reg = pt.get('ret_reg')
        if not frames or ret_reg is None:
            continue

        callee = frames[-1]
        depth = len(frames)
        lines_visited = []
        j = i
        while j >= 0:
            fs = execution_points[j]['stack_to_render']
            if len(fs) != depth or fs[-1]['frame_id'] != callee['frame_id']:
                break
            lines_visited.append(execution_points[j]['line'])
            j -= 1

        if frame_returns_scalar(lines_visited):
            callee['encoded_locals']['__return__'] = \
                ['C_DATA', '<register>', 'int', to_signed32(ret_reg)]


if __name__ == '__main__':
    parser = OptionParser(usage="Create an OPT trace from a Valgrind trace")
    parser.add_option("--create_jsvar", dest="js_varname", default=None,
                      help="Create a JavaScript variable out of the trace")
    parser.add_option("--jsondump", dest="jsondump", action="store_true", default=False,
                      help="Dump compact JSON as output")
    parser.add_option("--prettydump", dest="prettydump", action="store_true", default=False,
                      help="Dump pretty-printed JSON as output")
    parser.add_option("--end-of-trace-error-msg", dest="end_of_trace_error_msg", default=None,
                      help="Display this error message at the end of the trace")
    parser.add_option("--trace-truncated", dest="trace_truncated", action="store_true", default=False,
                      help="The vgtrace was cut off by the watchdog (byte/wall budget); label the trace as too long")

    (options, args) = parser.parse_args()

    if options.trace_truncated:
        # valgrind was killed before the program finished -- same meaning as
        # the in-band MAX_STEPS_EXCEEDED marker
        max_steps_exceeded = True

    fn = args[0]
    basename, ext = os.path.splitext(fn)
    assert ext in ('.c', '.cpp')
    cod = open(fn).read()
    source_lines = cod.split('\n')
    cur_record_lines = []

    success = True

    # parse at most VGTRACE_BYTE_BUDGET bytes: decoded points for a huge
    # vgtrace do not fit in the tracing container's RAM (256MB), and the
    # display cap would throw the excess away anyway. Stopping early means
    # the program ran longer than we can show -- same as the raw-step cap.
    bytes_read = 0
    stopped_at_byte_budget = False

    for line in open(basename + '.vgtrace'):
        bytes_read += len(line)
        line = line.strip()
        if line == RECORD_SEP:
            success = process_record(cur_record_lines)
            if not success:
                break
            cur_record_lines = []
            if bytes_read > VGTRACE_BYTE_BUDGET:
                stopped_at_byte_budget = True
                max_steps_exceeded = True
                break
        else:
            cur_record_lines.append(line)

    # only parse final record if we've been successful so far; i.e., die
    # on the first failed parse
    if success and not stopped_at_byte_budget:
        success = process_record(cur_record_lines)

    # now do some filtering action based on heuristics
    filtered_execution_points = []

    for pt in all_execution_points:
        # any execution point with a 0x0 frame pointer is bogus
        # (frame_id is 'FP_depth', so match on the FP prefix)
        frame_ids = [e['frame_id'] for e in pt['stack_to_render']]
        func_names = [e['func_name'] for e in pt['stack_to_render']]
        if any(fid.startswith('0x0_') for fid in frame_ids):
            continue

        # NB: there used to be a "duplicate frame_ids are bogus" filter here
        # from when frame_id was the bare FP. It threw away every step inside
        # a member function (methods share their caller's FP -- see the
        # frame_id comment in process_json_obj). Depth-suffixed frame_ids are
        # unique by construction, and transient mid-prologue points (the
        # thing the filter actually caught) are absorbed by the frame_id
        # continuity check below.

        # any point with a weird '???' function name is bogus
        # but we shouldn't have any more by now
        #assert '???' not in func_names # actually nevermind on this for now - we still sometimes get '???' so just skip those
        if '???' in func_names:
            continue

        #print func_names, frame_ids
        filtered_execution_points.append(pt)


    final_execution_points = []
    if filtered_execution_points:
        final_execution_points.append(filtered_execution_points[0])
        # finally, make sure that each successive entry contains
        # frame_ids that are either identical to the previous one, or
        # differ by the addition or subtraction of one element at the
        # end, which represents a function call or return, respectively.
        # there are weird cases like:
        #
        # [u'main'] [u'0xFFEFFFE30']
        # [u'main'] [u'0xFFEFFFE30']
        # [u'foo'] [u'0xFFEFFFDC0'] <- bogus
        # [u'main', u'foo'] [u'0xFFEFFFE30', u'0xFFEFFFDC0']
        # [u'main', u'foo'] [u'0xFFEFFFE30', u'0xFFEFFFDC0']
        #
        # where the middle entry should be FILTERED OUT since it's
        # missing 'main' for some reason
        for prev, cur in zip(filtered_execution_points, filtered_execution_points[1:]):
            prev_frame_ids = [e['frame_id'] for e in prev['stack_to_render']]
            cur_frame_ids = [e['frame_id'] for e in cur['stack_to_render']]

            # identical, we're good to go
            if prev_frame_ids == cur_frame_ids:
                final_execution_points.append(cur)
            elif len(prev_frame_ids) < len(cur_frame_ids):
                # cur_frame_ids is prev_frame_ids + 1 extra element on
                # the end -> function call
                if prev_frame_ids == cur_frame_ids[:-1]:
                    final_execution_points.append(cur)
            elif len(prev_frame_ids) > len(cur_frame_ids):
                # cur_frame_ids is prev_frame_ids MINUS the last element on
                # the end -> function return
                if cur_frame_ids == prev_frame_ids[:-1]:
                    final_execution_points.append(cur)

        assert len(final_execution_points) <= len(filtered_execution_points)

        cur_ind = 1
        # now mark 'call' and' 'return' events via the same heuristic as above
        for prev, cur in zip(final_execution_points, final_execution_points[1:]):
            prev_frame_ids = [e['frame_id'] for e in prev['stack_to_render']]
            cur_frame_ids = [e['frame_id'] for e in cur['stack_to_render']]

            if len(prev_frame_ids) < len(cur_frame_ids):
                if prev_frame_ids == cur_frame_ids[:-1]:
                    cur['event'] = 'call'
                # optimization -- when you find a 'call' instruction,
                # look ahead in the trace to find all *consecutive*
                # entries with the same frame_ids and on the same line,
                # then eliminate those from the trace.
                #
                # if we don't do this optimization, then the visualizer
                # will show multiple steps for entering a function call,
                # with formal parameters being filled in with their
                # values along the way; while this is somewhat
                # informative, it's also kinda extraneous. instead, we
                # want to skip over all parameter initialization and
                # jump right into the function body right away with all
                # the parameters initialized
                lookahead = final_execution_points[cur_ind+1:] # start at the next index
                for future_step in lookahead:
                    future_frame_ids = [e['frame_id'] for e in future_step['stack_to_render']]
                    if cur_frame_ids == future_frame_ids and cur['line'] == future_step['line']:
                        future_step['to_delete'] = True
                    else:
                        # BREAK AS SOON AS you change lines or stack
                        # frame_id contents, since we don't want to be
                        # over-eager and cut out *non-consecutive*
                        # elements from the trace
                        break
            elif len(prev_frame_ids) > len(cur_frame_ids):
                if cur_frame_ids == prev_frame_ids[:-1]:
                    prev['event'] = 'return'
            cur_ind += 1 # tricky indent

        # make the last statement a faux 'return', presumably from main
        if success:
            if options.end_of_trace_error_msg:
                # make last statement an exception if end_of_trace_error_msg passed in
                final_execution_points[-1]['event'] = 'exception'
                final_execution_points[-1]['exception_msg'] = options.end_of_trace_error_msg
            else:
                # make last statement a faux 'return', presumably from main
                final_execution_points[-1]['event'] = 'return'

        # cpp-tutor: must run on the still-undeduped final_execution_points
        # (one entry per traced instruction) -- it needs the fine-grained
        # per-instruction line history to find a frame's return statement,
        # which the ONLY_ONE_REC_PER_LINE/to_delete passes below collapse away.
        attach_return_values(final_execution_points)


    # kludgy: don't do to_delete for return events, since if we do this,
    # then we may be skipping return events for one-liner functions like
    #   int getInt() { return static_const_member;}
    # due to our above optimization to cut out all events on the same
    # line as a 'call' instruction. in a one-liner function, the call
    # and return are on the same line, so we don't want to delete the return
    for e in final_execution_points:
        if e['event'] == 'return':
            if 'to_delete' in e:
                del e['to_delete']


    # cpp-tutor: detect a single-line spin (while(true);) from the RAW stream
    # BEFORE ONLY_ONE_REC_PER_LINE collapses it. If the program hit the raw
    # instruction cap while stuck on one (line, frame) -- the tail of the raw
    # step_line stream is a long run of identical (line, frame) records -- it
    # is a genuine infinite loop the deduped stream can no longer show.
    #
    # NOTE: the "if success:" block above (which fires whenever record
    # parsing succeeded, independent of max_steps_exceeded) has already
    # relabeled final_execution_points[-1]['event'] to 'return', even when
    # the program was actually cut off at the raw cap. So this scan cannot
    # gate on event == 'step_line' for the tail point; it breaks only on a
    # 'call' (a genuinely new, deeper frame -- key comparison below also
    # catches this naturally, since a call changes the frame_id tuple).
    spin_at_cap = False
    if max_steps_exceeded:
        run = 0
        tail_key = None
        for elt in reversed(final_execution_points):
            if 'to_delete' in elt:
                continue
            if elt.get('event') == 'call':
                break
            key = (elt['line'],
                   tuple(f['frame_id'] for f in elt['stack_to_render']))
            if tail_key is None:
                tail_key = key
            if key != tail_key:
                break
            run += 1
        spin_at_cap = run >= SPIN_RUN

    # only keep the FIRST 'step_line' event for any given line, to match what
    # a line-level debugger would do
    # (try to do this before other optimizations)
    if ONLY_ONE_REC_PER_LINE:
        tmp = []
        prev_event = None
        prev_line = None
        prev_frame_ids = None

        for elt in final_execution_points:
            skip = False
            cur_event = elt['event']
            cur_line = elt['line']
            cur_frame_ids = [e['frame_id'] for e in elt['stack_to_render']]
            if prev_frame_ids:
                if cur_event == prev_event == 'step_line':
                    if cur_line == prev_line and cur_frame_ids == prev_frame_ids:
                        skip = True

            if not skip:
                tmp.append(elt)

            prev_event = cur_event
            prev_line = cur_line
            prev_frame_ids = cur_frame_ids

        final_execution_points = tmp # the ole' switcheroo

    # optimization: if we're returning to the SAME LINE in the
    # caller as it originally called this function with, then
    # skip this step since it's redundant. for example:
    '''
void* foo() {
void *x = malloc(1);
return x;
}
int main() {
void *x = foo(); // <-- there is an extraneous step here AFTER foo returns but
             //     before its return value is assigned to x. this optimization
             //     eliminates this step to clean up the trace a bit
}
    '''
    for prev, cur, next in zip(final_execution_points, final_execution_points[1:], final_execution_points[2:]):
        if prev['event'] == 'return' and len(prev['stack_to_render']) > 1:
            prev_caller = prev['stack_to_render'][-2]
            cur_top = cur['stack_to_render'][-1]
            # one additional subtle caveat is that we should delete only
            # if cur['func_name'] == next['func_name'] because otherwise
            # we will be directly jumping into another function without
            # first showing the return to cur, which may look JARRING
            if (cur_top['frame_id'] == prev_caller['frame_id']) and \
               (cur_top['line'] == prev_caller['line']) and \
               (cur['func_name'] == next['func_name']):
                cur['to_delete'] = True


    # now eliminate all steps before the first call to 'main' to clean up the trace,
    # especially for C++ code with weird pre-main initializers
    for e in final_execution_points:
        if e['func_name'] == 'main':
            break # GET OUT!
        else:
            e['to_delete'] = True


    for e in final_execution_points:
        if 'to_delete' in e:
            print >> sys.stderr, 'to_delete:', json.dumps(e)
    final_execution_points = [e for e in final_execution_points if 'to_delete' not in e]


    # cpp-tutor: intelligent step cap. Detect true infinite loops (exact state
    # repetition) vs. programs merely too long (raw cap hit), and trim/label
    # accordingly. Replaces the old fixed 150-step truncation.
    final_execution_points = apply_step_limits(
        final_execution_points, max_steps_exceeded, spin_at_cap=spin_at_cap)


    # produce the final trace, voila!
    final_res = {'code': cod, 'trace': final_execution_points}

    # use sort_keys to get some sensible ordering on object keys
    if options.js_varname:
        s = json.dumps(final_res, indent=2, sort_keys=True)
        print 'var ' + options.js_varname + ' = ' + s + ';'
    elif options.jsondump:
        print json.dumps(final_res, sort_keys=True)
    elif options.prettydump:
        print json.dumps(final_res, indent=2, sort_keys=True)
    else:
        assert False

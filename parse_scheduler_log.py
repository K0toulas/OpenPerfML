#!/usr/bin/env python3
import re
import sys
from collections import OrderedDict, defaultdict, Counter

ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

def clean(s: str) -> str:
    return ANSI_ESCAPE.sub("", s).replace("\r", "")

# Strict coreset grammar: "0", "0-7", "0-3,6,8-11"
CORESET = r"(?:\d+(?:-\d+)?)(?:,(?:\d+(?:-\d+)?))*"

RE_SET_AFF = re.compile(
    r"\[SCHEDULER\]\s*:?\s*Setting affinity for PID\s+(\d+)\s+to coreset\s+(" + CORESET + r")"
)

# Table header variants:
# [SCHEDULER]    PID     TID PSR CMD
#     PID     TID PSR CMD
RE_TABLE_HDR = re.compile(r"^(?:\[\s*SCHEDULER\s*\])?\s*PID\s+TID\s+PSR\s+CMD\s*$")
RE_TABLE_PROC_ROW = re.compile(r"^\s*(\d+)\s+-\s+-\s+(.*)$")
RE_TABLE_TID_ROW = re.compile(r"^\s*-\s+(\d+)\s+(\d+)\s+-\s*$")

def classify_psr(psr: int) -> str:
    if 0 <= psr <= 7:
        return "P"
    if 8 <= psr <= 15:
        return "E"
    return "OTHER"

def summarize_psr_changes(psr_changes):
    """
    psr_changes: list of (line_no, psr) representing *changes only*.
    """
    if not psr_changes:
        return "(no PSR observations)"

    psrs = [psr for _, psr in psr_changes]
    first = psrs[0]
    last = psrs[-1]
    unique = sorted(set(psrs))
    n_changes = len(psrs) - 1  # number of transitions recorded

    if len(unique) == 1:
        return f"stable at {unique[0]} (last={last})"

    # detect pure 2-way alternation (no repeats)
    if len(unique) == 2:
        a, b = unique[0], unique[1]
        ok = True
        for i in range(1, len(psrs)):
            if psrs[i] == psrs[i - 1]:
                ok = False
                break
        if ok:
            return f"{a}<->{b} toggled {n_changes} times (first={first} last={last})"

    c = Counter(psrs)
    most = c.most_common(3)
    most_str = ", ".join([f"{cpu}({cnt})" for cpu, cnt in most])
    return f"unique={unique} changes={n_changes} most_common={most_str} (first={first} last={last})"

def count_ep_moves(psr_changes):
    """
    Counts transitions between E and P based on the PSR change list.
    Returns (e_to_p, p_to_e, other_moves)
    """
    if not psr_changes or len(psr_changes) < 2:
        return 0, 0, 0

    psrs = [psr for _, psr in psr_changes]
    e_to_p = 0
    p_to_e = 0
    other = 0

    prev_cls = classify_psr(psrs[0])
    for psr in psrs[1:]:
        cur_cls = classify_psr(psr)
        if prev_cls == "E" and cur_cls == "P":
            e_to_p += 1
        elif prev_cls == "P" and cur_cls == "E":
            p_to_e += 1
        elif prev_cls != cur_cls:
            other += 1
        prev_cls = cur_cls

    return e_to_p, p_to_e, other

def main():
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print("  python3 pid_tid_psr_and_coresets.py scheduler.log", file=sys.stderr)
        print("  python3 pid_tid_psr_and_coresets.py scheduler.log --full", file=sys.stderr)
        return 2

    path = None
    full = False

    for arg in sys.argv[1:]:
        if arg == "--full":
            full = True
        else:
            path = arg

    if path is None:
        print("Error: missing scheduler.log path", file=sys.stderr)
        return 2

    # pid -> {"cmd": str, "tids": OrderedDict(tid -> {"first_line": int})}
    pid_map = OrderedDict()

    # Affinity: id (pid or tid) -> [coreset1, coreset2, ...] (dedup)
    id_aff_seq = defaultdict(list)
    id_last_aff = {}

    # PSR timeline: pid -> tid -> [(line_no, psr), ...] (dedup consecutive)
    psr_seq = defaultdict(lambda: defaultdict(list))
    psr_last = {}  # (pid, tid) -> last_psr

    # Summary counters across the whole log (from table observations)
    p_obs = 0
    e_obs = 0
    other_obs = 0

    in_table = False
    current_pid = None

    with open(path, "r", errors="replace") as f:
        for ln, raw in enumerate(f, start=1):
            line = clean(raw).rstrip("\n")

            # affinity lines
            m = RE_SET_AFF.search(line)
            if m:
                the_id = int(m.group(1))
                coreset = m.group(2).strip()
                if id_last_aff.get(the_id) != coreset:
                    id_aff_seq[the_id].append(coreset)
                    id_last_aff[the_id] = coreset

            # table start
            if RE_TABLE_HDR.match(line.strip()):
                in_table = True
                current_pid = None
                continue

            if in_table:
                m = RE_TABLE_PROC_ROW.match(line)
                if m:
                    current_pid = int(m.group(1))
                    cmd = m.group(2).strip()
                    if current_pid not in pid_map:
                        pid_map[current_pid] = {"cmd": cmd, "tids": OrderedDict()}
                    else:
                        if not pid_map[current_pid]["cmd"]:
                            pid_map[current_pid]["cmd"] = cmd
                    continue

                m = RE_TABLE_TID_ROW.match(line)
                if m and current_pid is not None:
                    tid = int(m.group(1))
                    psr = int(m.group(2))

                    if tid not in pid_map[current_pid]["tids"]:
                        pid_map[current_pid]["tids"][tid] = {"first_line": ln}

                    cls = classify_psr(psr)
                    if cls == "P":
                        p_obs += 1
                    elif cls == "E":
                        e_obs += 1
                    else:
                        other_obs += 1

                    # record only changes for the per-thread PSR timeline
                    key = (current_pid, tid)
                    if psr_last.get(key) != psr:
                        psr_seq[current_pid][tid].append((ln, psr))
                        psr_last[key] = psr
                    continue

                # end-of-table heuristic
                if line.startswith("[SCHEDULER]:") or line.startswith("[SCHEDULER ERROR]:") or line.strip() == "" or line.strip().startswith("^C"):
                    in_table = False
                    current_pid = None

    if not pid_map:
        print("No verification tables found (no PID/TID/PSR table).")
        return 0

    total_e_to_p = 0
    total_p_to_e = 0
    total_other_moves = 0

    for pid, info in pid_map.items():
        cmd = info["cmd"]
        tids = list(info["tids"].keys())

        print(f"PID {pid}" + (f"  CMD: {cmd}" if cmd else ""))

        if pid in id_aff_seq:
            print("  PID affinity coresets:", " -> ".join(id_aff_seq[pid]))
        else:
            print("  PID affinity coresets: (none logged)")

        print(f"  Threads: {len(tids)}")
        for tid in tids:
            aff = id_aff_seq.get(tid, [])
            aff_str = (" -> ".join(aff)) if aff else "(no affinity changes logged)"

            changes = psr_seq[pid].get(tid, [])
            e_to_p, p_to_e, other_moves = count_ep_moves(changes)
            total_e_to_p += e_to_p
            total_p_to_e += p_to_e
            total_other_moves += other_moves

            print(f"    TID {tid}:")
            if full:
                if changes:
                    psr_chain = " -> ".join(str(psr) for _, psr in changes)
                    last_psr = changes[-1][1]
                    print(f"      psr_seq_full: {psr_chain}  (last={last_psr})")
                else:
                    print("      psr_seq_full: (no PSR observations)")
            else:
                print(f"      psr_seq: {summarize_psr_changes(changes)}")

            print(f"      moves: E->P={e_to_p}  P->E={p_to_e}" + (f"  other={other_moves}" if other_moves else ""))
            print(f"      coreset_seq: {aff_str}")

        print()

    print("=== PSR observation summary (from verification table rows) ===")
    print(f"observed on P cores {p_obs} times (PSR 0-7)")
    print(f"observed on E cores {e_obs} times (PSR 8-15)")
    if other_obs:
        print(f"observed on other PSR values {other_obs} times")

    print("\n=== PSR move summary (from PSR change sequences) ===")
    print(f"moved E->P {total_e_to_p} times")
    print(f"moved P->E {total_p_to_e} times")
    if total_other_moves:
        print(f"moved between P/E/OTHER {total_other_moves} times")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
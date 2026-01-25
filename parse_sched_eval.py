import re
import sys
from collections import defaultdict

LINE_RE = re.compile(
    r"SCHED_EVAL\s+pid=(?P<pid>\d+)\s+"
    r"yP=(?P<yP>[-+0-9.eE]+)\s+"
    r"yE=(?P<yE>[-+0-9.eE]+)\s+"
    r"chosen=(?P<chosen>\S+)\s+"
    r"actual_P=(?P<aP>\d+)\s+"
    r"actual_E=(?P<aE>\d+)\s+"
    r"actual_other=(?P<aO>\d+)\s+"
    r"total=(?P<tot>\d+)"
)

def infer_actual_majority(aP, aE):
    if aP > aE:
        return "P"
    if aE > aP:
        return "E"
    return "TIE"

def infer_chosen_side(chosen):
    # adjust if your strings differ
    if chosen in ("0-7", "P_CORESET", "P"):
        return "P"
    if chosen in ("8-15", "E_CORESET", "E"):
        return "E"
    if chosen in ("0-15", "ALL_CORESET", "ALL"):
        return "ALL"
    return "UNK"

def main(path):
    rows = []
    by_pid = defaultdict(list)

    with open(path, "r", errors="replace") as f:
        for line in f:
            m = LINE_RE.search(line)
            if not m:
                continue

            pid = int(m.group("pid"))
            yP = float(m.group("yP"))
            yE = float(m.group("yE"))
            chosen = m.group("chosen")

            aP = int(m.group("aP"))
            aE = int(m.group("aE"))
            aO = int(m.group("aO"))
            tot = int(m.group("tot"))

            denom = tot if tot > 0 else 1
            p_pct = 100.0 * aP / denom
            e_pct = 100.0 * aE / denom

            pred_side = "P" if yP >= yE else "E"
            chosen_side = infer_chosen_side(chosen)
            actual_side = infer_actual_majority(aP, aE)

            # A simple correctness definition:
            # - if chosen is P or E, we expect actual majority to match
            # - if chosen is ALL, mark N/A
            if chosen_side in ("P", "E"):
                ok = (actual_side == chosen_side)
            else:
                ok = None

            row = {
                "pid": pid,
                "yP": yP,
                "yE": yE,
                "pred_side": pred_side,
                "chosen": chosen,
                "chosen_side": chosen_side,
                "actual_P": aP,
                "actual_E": aE,
                "actual_other": aO,
                "total": tot,
                "p_pct": p_pct,
                "e_pct": e_pct,
                "actual_side": actual_side,
                "ok": ok,
            }
            rows.append(row)
            by_pid[pid].append(row)

    # Print per-row table
    print("pid  yP        yE        pred chosen  actP actE tot   P%     E%     ok")
    for r in rows:
        ok_str = "NA" if r["ok"] is None else ("OK" if r["ok"] else "BAD")
        print(f'{r["pid"]:>4} {r["yP"]:>9.4f} {r["yE"]:>9.4f} '
              f'{r["pred_side"]:>4} {r["chosen"]:>6} '
              f'{r["actual_P"]:>4} {r["actual_E"]:>4} {r["total"]:>4} '
              f'{r["p_pct"]:>6.1f}% {r["e_pct"]:>6.1f}% {ok_str:>4}')

    # Summary
    counted = 0
    correct = 0
    for r in rows:
        if r["ok"] is None:
            continue
        counted += 1
        if r["ok"]:
            correct += 1

    print("\nSummary:")
    print(f"  total eval rows: {len(rows)}")
    print(f"  rows with P/E chosen: {counted}")
    if counted:
        print(f"  correctness (chosen matches actual majority): {100.0*correct/counted:.1f}% ({correct}/{counted})")

    # Per-PID quick view
    print("\nPer-PID last decision:")
    for pid, lst in sorted(by_pid.items()):
        last = lst[-1]
        ok_str = "NA" if last["ok"] is None else ("OK" if last["ok"] else "BAD")
        print(f'  pid={pid} chosen={last["chosen"]} yP={last["yP"]:.4f} yE={last["yE"]:.4f} '
              f'P%={last["p_pct"]:.1f} E%={last["e_pct"]:.1f} {ok_str}')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_sched_eval.py <scheduler_log_file>")
        sys.exit(1)
    main(sys.argv[1])
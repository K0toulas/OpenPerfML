import csv
import json
import math
import numpy as np

# FEATURES = [
#     "IPC",
#     "Cache_Miss_Ratio",
#     "Uop_per_Cycle",
#     "MemStall_per_Mem",
#     "MemStall_per_Inst",
#     "FaultRate_per_mem",
#     "RChar_per_Cycle",
#     "WChar_per_Cycle",
#     "RBytes_per_Cycle",
#     "WBytes_per_Cycle",
# ]
FEATURES = [
    "cycles_per_ms",
    "IPC",
    "Cache_Miss_Ratio",
    "MemStall_per_Mem",
    "MemStall_per_Inst",
]

TARGET = "inst_per_ms"

def load_xy(path, warmup_windows=0, min_dt_ms=1.0):
    X, y = [], []
    with open(path, "r", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            w = int(float(row["window_idx"]))
            dt = float(row.get("dt_ms", "0") or 0.0)
            if w <= warmup_windows:
                continue
            if dt < min_dt_ms:   # skip weird first/short windows
                continue

            try:
                xi = [float(row[k]) for k in FEATURES]
                yi = float(row[TARGET])
            except ValueError:
                continue

            # Drop NaN/inf rows
            if (not math.isfinite(yi)) or any(not math.isfinite(v) for v in xi):
                continue

            X.append(xi)
            y.append(yi)

    return np.array(X, dtype=np.float64), np.array(y, dtype=np.float64)

def fit_ridge(X, y, alpha=1e-6):
    # Add intercept
    X1 = np.hstack([np.ones((X.shape[0], 1)), X])
    # Closed-form ridge: (X^T X + aI)^-1 X^T y
    I = np.eye(X1.shape[1])
    I[0, 0] = 0.0  # don't regularize intercept
    w = np.linalg.solve(X1.T @ X1 + alpha * I, X1.T @ y)
    return w  # [b0, b1..]

def metrics(X, y, w):
    X1 = np.hstack([np.ones((X.shape[0], 1)), X])
    yhat = X1 @ w
    err = yhat - y
    rmse = float(np.sqrt(np.mean(err**2)))
    mae = float(np.mean(np.abs(err)))
    # R^2
    ss_res = float(np.sum(err**2))
    ss_tot = float(np.sum((y - np.mean(y))**2))
    r2 = float(1.0 - ss_res / ss_tot) if ss_tot > 0 else float("nan")
    return rmse, mae, r2

def fit_one(path, warmup_windows=0, alpha=1e-6):
    X, y = load_xy(path, warmup_windows=warmup_windows)
    if X.shape[0] < X.shape[1] + 5:
        raise RuntimeError(f"Not enough rows in {path}: got {X.shape[0]}")

    w = fit_ridge(X, y, alpha=alpha)
    rmse, mae, r2 = metrics(X, y, w)

    model = {
        "features": FEATURES,
        "target": TARGET,
        "intercept": float(w[0]),
        "weights": {FEATURES[i]: float(w[i+1]) for i in range(len(FEATURES))},
        "alpha": alpha,
        "n_rows": int(X.shape[0]),
        "rmse": rmse,
        "mae": mae,
        "r2": r2,
    }
    return model

if __name__ == "__main__":
    # adjust warmup if you used WARMUP_WINDOWS=...
    WARMUP = 5
    ALPHA = 1e-6

    model_P = fit_one("train_P.csv", warmup_windows=WARMUP, alpha=ALPHA)
    model_E = fit_one("train_E.csv", warmup_windows=WARMUP, alpha=ALPHA)

    print("P model:", json.dumps(model_P, indent=2))
    print("E model:", json.dumps(model_E, indent=2))

    with open("model_P.json", "w") as f:
        json.dump(model_P, f, indent=2)
    with open("model_E.json", "w") as f:
        json.dump(model_E, f, indent=2)

    print("\nWrote model_P.json and model_E.json")
    import csv, json, math
import numpy as np

WARMUP = 5
TRAIN_FRAC = 0.7
TARGET = "inst_per_ms"

def load_rows(csv_path):
    rows=[]
    with open(csv_path) as f:
        r=csv.DictReader(f)
        for row in r:
            widx=int(float(row.get("window_idx","0")))
            if widx <= WARMUP:
                continue
            # keep only finite rows
            ok=True
            for k in FEATURES+[TARGET]:
                v=float(row[k])
                if not math.isfinite(v):
                    ok=False
                    break
            if not ok:
                continue
            rows.append(row)
    rows.sort(key=lambda rr: int(float(rr.get("window_idx","0"))))
    return rows

def rows_to_xy(rows):
    X=[]; y=[]
    for row in rows:
        X.append([float(row[k]) for k in FEATURES])
        y.append(float(row[TARGET]))
    return np.array(X, dtype=np.float64), np.array(y, dtype=np.float64)

def ridge_fit_closed_form(X, y, alpha=1e-6):
    # add intercept
    X1=np.hstack([np.ones((X.shape[0],1)), X])
    I=np.eye(X1.shape[1], dtype=np.float64)
    I[0,0]=0.0  # don't regularize intercept
    w=np.linalg.solve(X1.T@X1 + alpha*I, X1.T@y)
    return w  # [intercept, weights...]

def metrics(y, yhat):
    err=yhat-y
    rmse=float(np.sqrt(np.mean(err**2)))
    mae=float(np.mean(np.abs(err)))
    ss_res=float(np.sum(err**2))
    ss_tot=float(np.sum((y-np.mean(y))**2))
    r2=1.0-ss_res/ss_tot if ss_tot>0 else float("nan")
    corr=float(np.corrcoef(y,yhat)[0,1]) if len(y)>1 else float("nan")
    return {"rmse": rmse, "mae": mae, "r2": r2, "corr": corr}

def train_eval(csv_path, model_out, alpha=1e-6):
    rows=load_rows(csv_path)
    n=len(rows)
    n_train=int(TRAIN_FRAC*n)
    train_rows=rows[:n_train]
    test_rows=rows[n_train:]

    Xtr,ytr=rows_to_xy(train_rows)
    Xte,yte=rows_to_xy(test_rows)

    w=ridge_fit_closed_form(Xtr,ytr,alpha=alpha)

    def pred(X):
        X1=np.hstack([np.ones((X.shape[0],1)), X])
        return X1@w

    yhat_tr=pred(Xtr)
    yhat_te=pred(Xte)

    mtr=metrics(ytr,yhat_tr)
    mte=metrics(yte,yhat_te)

    model={
        "features": FEATURES,
        "target": TARGET,
        "intercept": float(w[0]),
        "weights": {FEATURES[i]: float(w[i+1]) for i in range(len(FEATURES))},
        "alpha": alpha,
        "n_rows_total": n,
        "n_rows_train": len(ytr),
        "n_rows_test": len(yte),
        "train": mtr,
        "test": mte,
        "split": {"warmup_windows": WARMUP, "train_frac": TRAIN_FRAC, "method": "time_by_window_idx"},
    }

    print("\nModel for", csv_path)
    print(" train:", mtr)
    print(" test :", mte)

    with open(model_out,"w") as f:
        json.dump(model,f,indent=2)
    return model

train_eval("train_P.csv","model_P.json")
train_eval("train_E.csv","model_E.json")
print("\nWrote model_P.json and model_E.json")
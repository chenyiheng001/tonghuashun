import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests, time, hashlib, random, string, json
from tkinter import filedialog

# ───────────────── 业务函数 ─────────────────
def generate_sign(secret: str):
    ts = int(time.time())
    nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    raw = f"timestamp={ts}&secret={secret}&nonce={nonce}"
    return ts, nonce, hashlib.md5(raw.encode()).hexdigest()

def get_token():
    url, appid, secret = token_url.get().strip(), appid_var.get().strip(), secret_var.get().strip()
    if not (url and appid and secret):
        messagebox.showwarning("缺少参数", "请填 Token URL / APPID / SECRET")
        return
    try:
        r = requests.post(url, {"appid": appid, "secret": secret}, timeout=10)
        r.raise_for_status(); j = r.json()
        if j["code"] != 0: raise RuntimeError(j)
        token_var.set(j["data"]["token"])
        log("√ 获取 Token 成功")
    except Exception as e:
        log(f"× 获取 Token 失败：{e}")

def push_result():
    base_url, token, secret, broker = push_url.get().strip(), token_var.get().strip(), secret_var.get().strip(), broker_id.get().strip()
    if not (base_url and token and secret and broker):
        messagebox.showwarning("缺少参数", "请填 Push URL / Token / SECRET / broker_id")
        return
    # 取用户输入
    res_success = 1 if result_choice.get() == "成功" else 0
    reason_str  = "0&0&0&0&0&0&0&0&0&0" if res_success else "1&0&0&1&0&0&0&0&0&0"
    sample = {
        "broker_id": broker,
        "client_id": client_id.get().strip(),
        "zjzh" : yesno_to_int(zj_var.get()),
        "sa"   : yesno_to_int(sa_var.get()),
        "ha"   : yesno_to_int(ha_var.get()),
        "sfcg" : yesno_to_int(sfcg_var.get()),
        "result" : res_success,
        "reason" : reason_str,
        "success_at": int(time.time())
    }
    ts, nonce, sign = generate_sign(secret)
    full = f"{base_url}?timestamp={ts}&sign={sign}&nonce={nonce}"
    hdr = {"Access-Token": token, "Content-Type": "application/json;charset=UTF-8"}
    try:
        r = requests.post(full, json=[sample], headers=hdr, timeout=10)
        r.raise_for_status(); j = r.json()
        log(("√ 推送成功" if j["code"]==0 else f"× 推送失败:{j}") + f" → {sample}")
    except Exception as e:
        log(f"× 请求异常：{e}")

def yesno_to_int(text):  # “是”→1，“否”→0
    return 1 if text == "是" else 0

def log(msg): status.insert(tk.END, msg + "\n"); status.see(tk.END)

# ───────────────── GUI ─────────────────
root = tk.Tk(); root.title("同花顺开户结果推送工具 v0.2")

# ── 最上方 Push URL ──
push_url = tk.StringVar()
ttk.Label(root, text="Push URL").grid(row=0, column=0, sticky="e", padx=6, pady=4)
ttk.Entry(root, textvariable=push_url, width=88).grid(row=0, column=1, columnspan=2, sticky="we", pady=4)

# ── 左栏：Token 获取 ──
lf = ttk.LabelFrame(root, text="Token 获取参数")
lf.grid(row=1, column=0, columnspan=2, padx=6, pady=4, sticky="nsew")
appid_var, secret_var, token_url, token_var, broker_id = (tk.StringVar() for _ in range(5))
broker_id.set("311")

for i,(lbl,var) in enumerate([
    ("Token URL",  token_url),
    ("APPID",      appid_var),
    ("SECRET",     secret_var),
    ("Token(自动填)", token_var),
    ("broker_id",  broker_id)]):
    ttk.Label(lf, text=lbl).grid(row=i, column=0, sticky="e", pady=2)
    ttk.Entry(lf, textvariable=var, width=35).grid(row=i, column=1, pady=2, sticky="w")

ttk.Button(lf, text="获取 Token", command=get_token).grid(row=5, column=0, columnspan=2, pady=4, sticky="ew")

# ── 右栏：开户字段 ──
rf = ttk.LabelFrame(root, text="开户结果字段（选择 是/否）")
rf.grid(row=1, column=2, columnspan=2, padx=6, pady=4, sticky="nsew")

client_id = tk.StringVar()
for i,(lbl,var) in enumerate([
    ("客户标识 client_id", client_id)]):
    ttk.Label(rf, text=lbl).grid(row=i, column=0, sticky="e")
    ttk.Entry(rf, textvariable=var, width=27).grid(row=i, column=1, pady=2, sticky="w")

# 公用下拉：是/否
def make_yesno(var,row,text):
    ttk.Label(rf,text=text).grid(row=row,column=0,sticky="e")
    cb = ttk.Combobox(rf,textvariable=var,state="readonly",values=("是","否"),width=5)
    cb.grid(row=row,column=1,sticky="w"); cb.current(0)

zj_var, sa_var, ha_var, sfcg_var = (tk.StringVar(value="是") for _ in range(4))
make_yesno(zj_var, 1, "资金账号已开通")
make_yesno(sa_var, 2, "深 A 股东账号已开通")
make_yesno(ha_var, 3, "沪 A 股东账号已开通")
make_yesno(sfcg_var,4,"三方存管已开通")

# 成功 / 失败
result_choice = tk.StringVar(value="成功")
ttk.Label(rf,text="开户结果").grid(row=5,column=0,sticky="e")
ttk.Combobox(rf,textvariable=result_choice,state="readonly",
             values=("成功","失败"),width=5).grid(row=5,column=1,sticky="w")

ttk.Button(rf,text="推送开户结果",command=push_result)\
    .grid(row=6,column=0,columnspan=2,pady=4,sticky="ew")

# ── 底部日志 ──
status = scrolledtext.ScrolledText(root,height=8,width=120)
status.grid(row=2,column=0,columnspan=4,padx=6,pady=(0,6),sticky="nsew")
status.insert(tk.END,"▶ 日志输出...\n")

for i in range(4): root.columnconfigure(i,weight=1)
root.rowconfigure(2,weight=1)

def download_log():
    content = status.get("1.0", tk.END).strip()
    if not content:
        messagebox.showinfo("提示", "当前没有任何日志内容可保存。")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt")],
        title="保存日志记录为文本文件"
    )
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("成功", f"日志已保存至:\n{file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {e}")

# 添加按钮
ttk.Button(root, text="下载回传记录", command=download_log).grid(
    row=3, column=0, columnspan=4, padx=6, pady=(0, 6), sticky="ew"
)
root.mainloop()

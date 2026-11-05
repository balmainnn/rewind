
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
import threading,json,csv,datetime,html,platform
from rewind_collectors import collect_all
class App:
 def __init__(self,r):
  self.r=r; self.data=[]; self.busy=False
  r.title("REWIND | Windows Activity Timeline"); r.geometry("1120x660"); r.minsize(850,480)
  h=ttk.Frame(r,padding=12);h.pack(fill="x")
  ttk.Label(h,text="REWIND",font=("Segoe UI",22,"bold")).pack(anchor="w")
  ttk.Label(h,text="Windows forensic artifact collector & activity timeline").pack(anchor="w",pady=(0,9))
  b=ttk.Frame(h);b.pack(fill="x")
  self.btn=ttk.Button(b,text="Collect artifacts",command=self.start);self.btn.pack(side="left")
  for t,f in [("Export JSON","json"),("Export CSV","csv"),("Export HTML","html")]:ttk.Button(b,text=t,command=lambda x=f:self.export(x)).pack(side="left",padx=4)
  ttk.Button(b,text="Clear",command=self.clear).pack(side="left",padx=4)
  fl=ttk.Frame(r,padding=8);fl.pack(fill="x")
  ttk.Label(fl,text="Search").pack(side="left");self.q=tk.StringVar();e=ttk.Entry(fl,textvariable=self.q,width=38);e.pack(side="left",padx=5);e.bind("<KeyRelease>",lambda _:self.refresh())
  ttk.Label(fl,text="Category").pack(side="left",padx=8);self.cat=tk.StringVar(value="All");self.cb=ttk.Combobox(fl,textvariable=self.cat,state="readonly",values=["All"],width=24);self.cb.pack(side="left");self.cb.bind("<<ComboboxSelected>>",lambda _:self.refresh())
  self.status=tk.StringVar(value="Ready • Run as Administrator for broader access.")
  self.tree=ttk.Treeview(r,columns=("time","cat","src","desc","details"),show="headings")
  for c,t,w in zip(("time","cat","src","desc","details"),("Timestamp","Category","Source","Description","Details"),(160,145,160,340,290)):self.tree.heading(c,text=t);self.tree.column(c,width=w,anchor="w")
  self.tree.pack(fill="both",expand=True,padx=10,pady=8);ttk.Label(r,textvariable=self.status,relief="sunken",anchor="w").pack(side="bottom",fill="x")
 def start(self):
  if self.busy:return
  self.busy=True;self.btn.config(state="disabled");self.status.set("Collecting artifacts…");threading.Thread(target=self.worker,daemon=True).start()
 def worker(self):
  try:
   d,n=collect_all(lambda s:self.r.after(0,lambda:self.status.set(s)));self.data=d;self.r.after(0,lambda:self.done(n))
  except Exception as e:self.r.after(0,lambda:self.done([str(e)]))
 def done(self,n):
  self.busy=False;self.btn.config(state="normal");self.cb["values"]=["All"]+sorted(set(x["category"] for x in self.data));self.cat.set("All");self.refresh();self.status.set(f"{len(self.data)} artifacts • "+" | ".join(n[:2]))
 def refresh(self):
  self.tree.delete(*self.tree.get_children());q=self.q.get().lower()
  for x in sorted(self.data,key=lambda a:a.get("timestamp",""),reverse=True):
   if self.cat.get()!="All" and x["category"]!=self.cat.get():continue
   if q and q not in " ".join(str(v) for v in x.values()).lower():continue
   self.tree.insert("","end",values=tuple(x.get(k,"") for k in ("timestamp","category","source","description","details")))
 def clear(self):self.data=[];self.refresh();self.status.set("Cleared.")
 def export(self,fmt):
  if not self.data:messagebox.showinfo("No data","Collect artifacts first.");return
  p=filedialog.asksaveasfilename(defaultextension="."+fmt,filetypes=[(fmt.upper(),"*."+fmt)])
  if not p:return
  try:
   if fmt=="json":
    with open(p,"w",encoding="utf-8") as f:json.dump({"tool":"REWIND","generated":datetime.datetime.now().astimezone().isoformat(),"system":platform.platform(),"events":self.data},f,indent=2,ensure_ascii=False)
   elif fmt=="csv":
    with open(p,"w",newline="",encoding="utf-8-sig") as f:
     w=csv.DictWriter(f,fieldnames=["timestamp","category","source","description","details","path","severity"],extrasaction="ignore");w.writeheader();w.writerows(self.data)
   else:
    rows="".join("<tr>"+"".join("<td>"+html.escape(str(x.get(k,"")))+"</td>" for k in ("timestamp","category","source","description","details"))+"</tr>" for x in self.data)
    doc="<!doctype html><meta charset=utf-8><title>REWIND report</title><style>body{font:14px Segoe UI;background:#111;color:#ddd;margin:28px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #444;padding:7px;text-align:left}</style><h1>REWIND</h1><p>Validate findings against original evidence.</p><table><tr><th>Time</th><th>Category</th><th>Source</th><th>Description</th><th>Details</th></tr>"+rows+"</table>"
    with open(p,"w",encoding="utf-8") as f:f.write(doc)
   messagebox.showinfo("Export complete","Saved "+p)
  except Exception as e:messagebox.showerror("Export failed",str(e))
def run():
 r=tk.Tk()
 try:ttk.Style().theme_use("clam")
 except:pass
 App(r);r.mainloop()

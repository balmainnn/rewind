
import os,datetime,subprocess,re
from pathlib import Path
def stamp(t):
 try:return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")
 except:return ""
def add(o,c,s,d,details="",ts="",path="",sev="info"):o.append({"timestamp":ts,"category":c,"source":s,"description":str(d),"details":str(details),"path":str(path),"severity":sev})
def getpaths():
 h=Path.home();w=Path(os.environ.get("WINDIR",r"C:\Windows"))
 return {"Recent":h/"AppData/Roaming/Microsoft/Windows/Recent","Auto Jump Lists":h/"AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations","Custom Jump Lists":h/"AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations","Prefetch":w/"Prefetch","Startup":h/"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup","Downloads":h/"Downloads"}
def scan_dir(o,cat,p,limit=5000):
 n=0
 try:
  for f in p.iterdir():
   if n>=limit:break
   try:
    if f.is_file():
     s=f.stat();add(o,cat,cat,f.name,f"{s.st_size:,} bytes; modified {stamp(s.st_mtime)}",stamp(s.st_mtime),f);n+=1
   except OSError:pass
 except OSError:pass
def usb(o):
 try:
  import winreg
  kp=r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
  with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,kp) as root:
   i=0
   while True:
    try:name=winreg.EnumKey(root,i);i+=1
    except OSError:break
    with winreg.OpenKey(root,name) as sub:
     j=0
     while True:
      try:inst=winreg.EnumKey(sub,j);j+=1
      except OSError:break
      friendly=""
      try:
       with winreg.OpenKey(sub,inst) as k:friendly,_=winreg.QueryValueEx(k,"FriendlyName")
      except OSError:pass
      add(o,"USB devices","Registry",friendly or name,"Instance: "+inst,"","HKLM\\"+kp+"\\"+name+"\\"+inst)
 except Exception as e:add(o,"Collection notes","USB registry","USB history unavailable",e,sev="warning")
def logs(o,progress):
 qs=[("Security","Security","*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4688 or EventID=1102)]]"),("System","System","*[System[(EventID=7045 or EventID=6005 or EventID=6006 or EventID=6008)]]"),("PowerShell","Microsoft-Windows-PowerShell/Operational","*[System[(EventID=4103 or EventID=4104)]]")]
 for cat,log,q in qs:
  progress("Reading "+log+" event log…")
  try:
   p=subprocess.run(["wevtutil","qe",log,"/q:"+q,"/f:text","/rd:true","/c:250"],capture_output=True,text=True,timeout=30,encoding="utf-8",errors="replace",creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
   if p.returncode:add(o,"Collection notes",log,"Log unavailable or access denied",(p.stderr or "")[:400],sev="warning");continue
   for b in re.split(r"\r?\n\r?\n",p.stdout):
    if not b.strip():continue
    m=re.search(r"Event ID:\s*(\d+)",b,re.I);d=re.search(r"Date:\s*(.+)",b,re.I);eid=m.group(1) if m else "?";ts=d.group(1).strip() if d else ""
    try:ts=datetime.datetime.fromisoformat(ts.replace("Z","+00:00")).astimezone().isoformat(timespec="seconds")
    except:pass
    lines=[x.strip() for x in b.splitlines() if x.strip()]
    add(o,cat,log,"Event ID "+eid+" • "+(lines[0][:150] if lines else "Event")," | ".join(lines[1:8])[:1000],ts,sev="warning" if eid in ("1102","4104") else "info")
  except Exception as e:add(o,"Collection notes",log,"Event log query failed",e,sev="warning")
def collect_all(progress=lambda x:None):
 o=[]
 if os.name!="nt":return o,["Windows-only collectors"]
 for cat,p in getpaths().items():progress("Collecting "+cat+"…");scan_dir(o,cat,p,2500 if cat=="Downloads" else 5000)
 progress("Reading USB device registry…");usb(o);logs(o,progress)
 o.sort(key=lambda x:x.get("timestamp",""),reverse=True)
 return o,[f"{len(o):,} records","Read-only collection"]

"""Aggregate raw per-operation samples; CI is based on independent run means."""
import csv,json,math,statistics,sys,re
from pathlib import Path
folder=Path(sys.argv[1]);groups={};sizes=[];raw=[]
logs=sorted(folder.glob('*-run*.log'))
if not logs:raise SystemExit('No run logs found')
for path in logs:
    scheme,run=re.fullmatch(r'(.*)-run(\d+)\.log',path.name).groups();run=int(run)
    text=path.read_text(encoding='utf-8')
    if not text.rstrip().endswith('PASS') or '\nFAIL' in text:raise SystemExit('Incomplete or failed log: '+str(path))
    for line in text.splitlines():
        if line.startswith('BENCH '):
            d=json.loads(line[6:]);items=[(d['name'],0,d['samples_ns'])]
        elif line.startswith('SCALABILITY '):
            d=json.loads(line[12:]);items=[(d['stage'],d['idrl_n'],d['samples_ns'])]
        elif line.startswith('WITNESS '):
            d=json.loads(line[8:]);items=[('witness_'+s,d['idrl_n'],xs) for s,xs in d['samples_ns'].items()]
            if d['proof_bytes']!=144:raise SystemExit('Unexpected witness size')
            sizes.append(dict(run=run,idrl_n=d['idrl_n'],A_bytes=d['A_bytes'],B_bytes=d['B_bytes'],proof_bytes=d['proof_bytes']))
        else:continue
        for stage,n,xs in items:
            if not xs or min(xs)<0:raise SystemExit('Invalid samples')
            groups.setdefault((scheme,stage,n),[]).append((run,xs))
            raw.extend(dict(scheme=scheme,stage=stage,idrl_n=n,run=run,sample=i+1,ns=x) for i,x in enumerate(xs))
rows=[]
for (scheme,stage,n),parts in sorted(groups.items()):
    if len({r for r,_ in parts})!=len(parts):raise SystemExit('Duplicate stage in one process: '+stage)
    means=[statistics.mean(xs)/1e6 for _,xs in parts];xs=[v/1e6 for _,x in parts for v in x]
    mean=statistics.mean(means);lo=hi=''
    if len(means)==3:
        half=4.302652729911275*statistics.stdev(means)/math.sqrt(3);lo=mean-half;hi=mean+half
    elif len(means)!=1:raise SystemExit('Use one or three independent runs')
    rows.append(dict(scheme=scheme,stage=stage,idrl_n=n,processes=len(means),samples=len(xs),mean_ms=mean,variance_ms2=statistics.variance(xs),ci95_low_ms=lo,ci95_high_ms=hi))
def write(path,rows):
    if not rows:return
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
write(folder/'statistics.csv',rows);write(folder/'samples.csv',raw)
if sizes:
    wr=[dict(r,stage=r['stage'][len('witness_'):]) for r in rows if r['stage'] in ('witness_prover','witness_verifier')]
    write(folder/'witness/statistics.csv',wr);write(folder/'witness/proof_sizes.csv',sizes)
(folder/'analysis.json').write_text(json.dumps({'groups':len(rows),'timed_samples':len(raw),'ci':'95% Student t, df=2, across three process means; blank for one run','variance':'sample variance of all individual latency samples, ms^2','outlier_removal':False},indent=2),encoding='utf-8')
print('Analyzed',len(rows),'groups and',len(raw),'samples:',folder)

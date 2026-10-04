"""Edit TEXT/STYLE, then run this script. No experiment rerun is needed."""
from pathlib import Path
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--data',type=Path,default=Path(__file__).resolve().parents[1]/'results/reference/witness')
parser.add_argument('--font',default='Times New Roman')
args=parser.parse_args()
P=args.data
TEXT={
 'prover':'Prover time','verifier':'Verifier time',
 'x':'Number of revoked identities','time_y':'Computation time (ms)',
 'size_label':'Constant witness size: 144 bytes',
}
STYLE={'font_family':args.font,'font_size':8,'label_size':9,
       'tick_size':8,'legend_size':8,'annotation_size':8,'dpi':600,
       'colors':['#0072B2','#D55E00'],'markers':['o','s'],
       'figure_size':(3.5,2.65),'log_scale':True,'annotation_xy':(.96,.30),
       'line_width':1.1,'marker_size':3.4}
# Fail clearly if Times New Roman is absent, rather than silently substituting.
font_manager.findfont(STYLE['font_family'],fallback_to_default=False)
plt.rcParams.update({'font.family':STYLE['font_family'],'font.size':STYLE['font_size'],
 'axes.labelsize':STYLE['label_size'],'xtick.labelsize':STYLE['tick_size'],
 'ytick.labelsize':STYLE['tick_size'],'legend.fontsize':STYLE['legend_size'],
 'axes.linewidth':.7,'xtick.major.width':.7,'ytick.major.width':.7,
 'pdf.fonttype':42,'svg.fonttype':'none',
 'mathtext.fontset':'custom','mathtext.rm':args.font,
 'mathtext.it':args.font+':italic','mathtext.bf':args.font+':bold',
 'mathtext.sf':args.font,'mathtext.tt':args.font,
 'mathtext.cal':args.font,'mathtext.fallback':None})
with (P/'statistics.csv').open(encoding='utf-8-sig') as f:R=list(csv.DictReader(f))
with (P/'proof_sizes.csv').open(encoding='utf-8-sig') as f:S=list(csv.DictReader(f))
GRID=sorted({int(r['idrl_n']) for r in R})
OUT=P/'figures';OUT.mkdir(exist_ok=True)
assert {int(r['proof_bytes']) for r in S}=={144}
fig,ax=plt.subplots(figsize=STYLE['figure_size'])
for i,stage in enumerate(('prover','verifier')):
    rows=sorted([r for r in R if r['stage']==stage],key=lambda r:int(r['idrl_n']))
    assert [int(r['idrl_n']) for r in rows]==GRID
    if any(not r['ci95_low_ms'] or not r['ci95_high_ms'] for r in rows):
        raise SystemExit('This plot requires three process runs with 95% confidence intervals.')
    y=[float(r['mean_ms']) for r in rows]
    err=[[float(r['mean_ms'])-float(r['ci95_low_ms']) for r in rows],
         [float(r['ci95_high_ms'])-float(r['mean_ms']) for r in rows]]
    ax.errorbar(GRID,y,yerr=err,marker=STYLE['markers'][i],linestyle='-' if i==0 else '--',
                capsize=2,capthick=.7,elinewidth=.7,color=STYLE['colors'][i],
                markersize=STYLE['marker_size'],label=TEXT[stage],linewidth=STYLE['line_width'])
if STYLE['log_scale']:ax.set_yscale('log')
else:ax.set_ylim(bottom=0)
ax.set_xscale('log',base=2);ax.set_xticks(GRID)
ax.set_xticklabels([rf'$2^{{{n.bit_length()-1}}}$' if n&(n-1)==0 else str(n) for n in GRID])
ax.set_xlabel(TEXT['x']);ax.set_ylabel(TEXT['time_y'])
ax.grid(alpha=.23);ax.spines[['top','right']].set_visible(False)
ax.legend(loc='upper left',frameon=False)
ax.text(*STYLE['annotation_xy'],TEXT['size_label'],transform=ax.transAxes,
        ha='right',va='center',fontsize=STYLE['annotation_size'],
        bbox=dict(facecolor='white',edgecolor='none',alpha=.9,pad=2))
fig.tight_layout(pad=.5)
for ext in ('png','pdf','svg'):fig.savefig(OUT/f'accumulator_nonmembership.{ext}',dpi=STYLE['dpi'])
plt.close(fig)
print('Saved combined prover/verifier figure as PNG/PDF/editable SVG:',OUT)

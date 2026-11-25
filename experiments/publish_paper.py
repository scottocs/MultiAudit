#!/usr/bin/env python3
"""Embed the validated file-count experiment and plots in the main paper."""
import argparse
import hashlib
import json
import math
import re
import statistics
from pathlib import Path
from validate_results import DEFAULT, SCHEMES, validate, validate_response
from onchain.batch_report import load_results as load_onchain, latex_setup as onchain_setup, latex_results as onchain_results
from mobile_report import format_algorithm_names, load_results as load_mobile, latex_setup as mobile_setup, latex_results as mobile_results

ROOT=Path(__file__).resolve().parents[1]
DISPLAY={'ZhangTPDS23':r'BPCS~\cite{ZhangTPDS23}','MiaoSCIS2026':r'MKPDP~\cite{MiaoSCIS2026}','XuTIFS26':r'MPA~\cite{XuTIFS26}','MultiAudit':r'\MultiAudit{}','YuTC25':r'Yu et al.~\cite{YuTC25}'}
COLORS={'ZhangTPDS23':'228877','MiaoSCIS2026':'AA5588','XuTIFS26':'DD9933','MultiAudit':'3366AA','YuTC25':'889933'}
NAME=DISPLAY

def expected_aux(n,c):
 # Stable hypergeometric no-hit probability from log-gamma; no Monte Carlo.
 def touched(k):
  if k>n-c:return 1.
  if k==0:return 0.
  q=math.lgamma(n-k+1)-math.lgamma(n-k-c+1)-math.lgamma(n+1)+math.lgamma(n-c+1)
  return -math.expm1(q)
 counts=[]
 for l in range((n-1).bit_length()+1):
  b=1<<l;full,rem=divmod(n,b);counts.append(full*touched(b)+(touched(rem) if rem else 0))
 return sum(2*y-x for x,y in zip(counts,counts[1:]))

def payload(name,m,n,s,c,G=64):
 L=(n-1).bit_length()
 if name=='MultiAudit':return (m*c+2)*G+m*32+m*expected_aux(n,c)*32
 if name=='XuTIFS26':return m*(32+(c+1)*G+c*L*32)
 if name=='YuTC25':return m*(s*32+(c+1)*G+c*L*32)
 if name=='ZhangTPDS23':return 3*G+32
 if name=='MiaoSCIS2026':return 2*G+32
 raise ValueError(name)

def style_source()->str:
    colors='\n'.join(r'\definecolor{'+s+'}{HTML}{'+COLORS[s]+'}' for s in SCHEMES)
    return colors+r'''
\pgfplotsset{auditaxis/.style={
 width=0.98\linewidth,height=0.76\linewidth,scale only axis=false,
 font=\sffamily\scriptsize,
 tick label style={font=\sffamily\scriptsize,/pgf/number format/fixed,/pgf/number format/precision=2,/pgf/number format/1000 sep={}},
 label style={font=\sffamily\small},tick align=outside,
 axis x line*=bottom,axis y line*=left,
 tick style={black!45,line width=0.35pt},axis line style={black!50,line width=0.45pt},
 scaled ticks=false,xminorticks=false,yminorticks=false,
 enlarge x limits=0.12,enlarge y limits={upper,value=0.15},
 xmajorgrids=false,ymajorgrids=true,grid style={draw=black!10,line width=0.25pt},
 axis background/.style={fill=white},clip mode=individual}}
'''

def legend_source(names=None)->str:
    out=[r'\begin{tikzpicture}[font=\sffamily\footnotesize]']
    for i,s in enumerate(names or SCHEMES):
        color=s
        fill=color if s=='MultiAudit' else color+'!75'
        out += [r'\begin{scope}[xshift='+str(i*100)+'pt]',r'\filldraw[fill='+fill+',draw='+color+r'!90!black,line width=0.35pt] (0pt,-3pt) rectangle (10pt,4pt);',r'\node[anchor=west,inner sep=0pt] at (16pt,0pt) {'+DISPLAY[s]+r'};',r'\end{scope}']
    return '\n'.join(out+[r'\end{tikzpicture}'])+'\n'

def plot_source(rows,phase)->str:
    scenario,x,xlabel='vary_m','m','Number of files $m$'
    selected=[r for r in rows if r['scenario']==scenario and r['phase']==phase]
    xs=sorted({int(r[x]) for r in selected})
    names=[s for s in SCHEMES if any(r['scheme']==s for r in selected)]
    scale=1000. if phase=='Store' else 1.
    opts=['auditaxis',f'xlabel={{{xlabel}}}','ylabel={}','xtick={'+','.join(map(str,xs))+'}', 'ybar=0.8pt','bar width=4pt']
    logarithmic=phase=='Store'
    if logarithmic:
        low=min(float(r['milliseconds'])/scale for r in selected)
        opts+=['ymode=log','log origin=infty',f'ymin={10**math.floor(math.log10(low)):.8f}']
    else:opts+=['ymin=0']
    high=max(float(r['p75_ms'] or r['milliseconds'])/scale for r in selected)
    opts += [f'ymax={high*(1.65 if logarithmic else 1.22):.6f}']
    lines=[r'\begin{tikzpicture}',r'\begin{axis}['+','.join(opts)+']']
    for name in names:
        part=sorted((r for r in selected if r['scheme']==name),key=lambda r:int(r[x]))
        coords=[]
        for r in part:
            y=float(r['milliseconds'])/scale
            coord=f'({r[x]},{y:.8f})'
            if phase!='Store':coord+=f" += (0,{max(0,float(r['p75_ms'])/scale-y):.8f}) -= (0,{max(0,y-float(r['p25_ms'])/scale):.8f})"
            coords.append(coord)
        color=name
        style=f'draw={color}!90!black,fill={color}!75,line width=0.5pt'
        if name=='MultiAudit':style=f'draw={color},fill={color},line width=0.6pt'
        if phase!='Store':style+=r',error bars/.cd,y dir=both,y explicit,error bar style={color=black!65,draw=black!65,line width=0.4pt},error mark options={draw=black!65,rotate=90,mark size=1.2pt,line width=0.4pt}'
        lines += [r'\addplot+['+style+'] coordinates {'+' '.join(coords)+'};']
    return '\n'.join(lines+[r'\end{axis}',r'\end{tikzpicture}'])+'\n'

def communication_payloads():
    return {name:{m:payload(name,m,3907,80,690)/1e6 for m in [10,20,30,40]}
            for name in ['XuTIFS26','YuTC25','MultiAudit']}


def communication_figure():
    out=[r'\begin{figure}[t]',r'\centering',r'\begin{tikzpicture}',r'\begin{axis}[auditaxis,width=0.8\linewidth,height=0.66\linewidth,xlabel={Number of files $m$},ylabel={Response payload (MB)},xtick={10,20,30,40},ybar=0.4pt,bar width=8pt,ymin=0,ymax=14,legend style={font=\sffamily\scriptsize,draw=none,fill=none,at={(0.03,0.97)},anchor=north west,legend columns=1}]']
    for name,points in communication_payloads().items():
        color=name
        fill=color if name=='MultiAudit' else color+'!75'
        coords=' '.join(f'({m},{value:.8f})' for m,value in points.items())
        out += [r'\addplot+[draw='+color+'!90!black,fill='+fill+r',line width=0.5pt] coordinates {'+coords+'};',r'\addlegendentry{'+NAME[name]+'}']
    out += [r'\end{axis}',r'\end{tikzpicture}',r'\caption{Audit-response payload at $B=10$~MB per file, $s=80$, and $c=690$.}',r'\label{fig:vi_communication}',r'\end{figure}']
    return '\n'.join(out)


def merge_deployment_figures(s, mobile_count=40):
    labels = ['fig:vi_communication', 'fig:onchain_cost', 'fig:mobile_costs']
    blocks = []
    for label in labels:
        a = s.index('\\label{' + label + '}')
        start = list(re.finditer(r'\\begin\{figure\}', s[:a]))[-1].start()
        end = s.index('\\end{figure}', a) + len('\\end{figure}')
        block = s[start:end]
        plot = block[block.index('\\begin{tikzpicture}'):block.index('\\end{tikzpicture}') + len('\\end{tikzpicture}')]
        caption = dict(zip(labels, ['Audit response', 'EVM verification', 'iPhone computation']))[label]
        plot = re.sub(r'width=0\.(?:8|90|98)\\linewidth,height=0\.(?:66|65|76)\\linewidth',
                      r'width=0.98\\linewidth,height=0.82\\linewidth,label style={font=\\sffamily\\footnotesize}', plot)
        if label == labels[0]:
            plot = plot.replace('bar width=8pt', 'bar width=4pt')
        elif label == labels[1]:
            plot = plot.replace('bar width=6pt', 'bar width=3pt').replace('bar shift=-8pt', 'bar shift=-4pt').replace('bar shift=8pt', 'bar shift=4pt').replace('xshift=-8pt', 'xshift=-4pt').replace('xshift=8pt', 'xshift=4pt').replace('line width=1pt', 'line width=0.8pt')
        else:
            plot = plot.replace('ylabel={Time (ms)},xtick=', r'ylabel={Time (ms)},xlabel={\phantom{Number of files $m$}},xtick=').replace('bar width=10pt', 'bar width=7pt').replace('legend columns=3', 'legend columns=1').replace('at={(0.5,0.98)},anchor=north', 'at={(0.98,0.98)},anchor=north east')
        if label == labels[1]:
            lines = plot.splitlines()
            annotations = [line for line in lines if line.startswith(r'\node[font=\sffamily\tiny')]
            plot = '\n'.join(line for line in lines if line not in annotations)
            plot = plot.replace(r'\end{axis}', '\n'.join(annotations) + '\n' + r'\end{axis}')
            plot = plot.replace('shift=-4pt', 'shift=-5pt').replace('shift=4pt', 'shift=5pt')
        blocks.append((start, end, plot, caption))
    out = [r'\begin{figure*}[!t]', r'\centering']
    for i, ((_, _, plot, caption), label) in enumerate(zip(blocks, labels)):
        out += [r'\subfloat[' + caption + r'\label{' + label + r'}]{\begin{minipage}[t][1.72in][t]{0.32\textwidth}\vspace{0pt}\centering', plot, r'\end{minipage}}' + (r'\hfill' if i < 2 else '')]
    out += [r'\caption{Communication, on-chain verification, and mobile computation costs at $B=10$~MB per file, $s=80$, and $c=690$. Panel (c) uses forty files and a logarithmic time axis.}', r'\label{fig:deployment_costs}', r'\end{figure*}']
    merged = '\n'.join(out).replace('Panel (c) uses forty files', 'Panel (c) uses ' + str(mobile_count) + ' files')
    for start, end, _, _ in reversed(blocks):
        s = s[:start] + (merged if start == blocks[0][0] else '') + s[end:]
    for label, panel in zip(labels, 'abc'):
        s = s.replace(r'\ref{' + label + '}', r'\ref{fig:deployment_costs}(' + panel + ')')
    return s


def runtime_figure(rows):
    out=[r'\begin{figure*}[!t]',r'\centering',legend_source()+r'\par\smallskip']
    for i,phase in enumerate(['Store','ProofGen','Verify']):
        caption='Store (s)' if phase=='Store' else phase+' (ms)'
        out += [r'\subfloat['+caption+r']{\begin{minipage}{0.33\textwidth}\centering',plot_source(rows,phase),r'\end{minipage}}']
        if i<2:out.append(r'\hfill')
    out += [r'\caption{Runtime on the cloud platform versus file count for $B=10$~MB per file, $s=80$, and $c=690$. Store is measured once in seconds on a logarithmic axis. Online bars show median milliseconds and interquartile ranges over 30 fresh audits.}',r'\label{fig:vi_runtime_sweeps}',r'\end{figure*}']
    return '\n'.join(out)


def cloud_setup():
    return r'''Let $B$ denote the nominal size of each file. We fix $B=10$~MB (MB $=10^6$ bytes), corresponding to 10,001,920 encoded bytes per file after rounding to complete chunks. We set $s=80$, $c=690$, and $n=3907$, with 64-byte $\GG_1$ elements and 32-byte scalars and hashes, and vary $m\in\{10,20,30,40\}$. Baseline normalization follows Tables~\ref{tab:computation} and~\ref{tab:communication}. We emulate the cloud on a PC with an Apple M4 (10 logical cores, 16~GiB RAM, macOS~26.5.2) running native ARM64 Go~1.25.4. All schemes use BN254 through the Geth \texttt{bn256/cloudflare} backend, with shared MSM, field, and storage kernels. The library name BN256 refers here to the same BN254 curve used by the EVM helpers. MKPDP uses two keywords per file and $ns=312{,}560$ single-sector blocks per file, and queries all files. Online timings report medians over 30 fresh audits following warmup. Cloud timings exclude setup, input and challenge generation, encoding, and transfer. Store time includes tagging and authentication-state construction on the same platform and excludes input encoding, serialization, and upload. Verify measures optional off-chain public checking.
'''


def cloud_analysis(base):
    pgx = base['XuTIFS26']['ProofGen'] / base['MultiAudit']['ProofGen']
    pgz = base['ZhangTPDS23']['ProofGen'] / base['MultiAudit']['ProofGen']
    vz = base['ZhangTPDS23']['Verify'] / base['MultiAudit']['Verify']
    text = r'''\paragraph{Storage and scaling}
Fig.~\ref{fig:vi_runtime_sweeps}(a) shows that Store time grows with the file count. MultiAudit remains close to MPA~\cite{XuTIFS26} and Yu et al.~\cite{YuTC25} because all three generate a commitment tag for every chunk and build complete per-file authentication trees. CMMs compact the sampled paths during audits rather than reduce initial tagging. This matches the design goal of reducing repeated online work while keeping owner Store costs comparable. The larger costs of BPCS~\cite{ZhangTPDS23} and MKPDP~\cite{MiaoSCIS2026} reflect their signed-tag and searchable-data constructions, respectively, rather than equivalent Store workloads.

\paragraph{Proof generation}
Fig.~\ref{fig:vi_runtime_sweeps}(b) shows the benefit of moving aggregation before commitment. MultiAudit commits to two combined quotient polynomials, whereas MPA~\cite{XuTIFS26} commits to one quotient per file. Returning CMM-authenticated tags also avoids the signed-tag aggregation performed by BPCS~\cite{ZhangTPDS23}. '''
    text += f"At forty files, these design choices yield proof-generation speedups of {pgx:.2f}$\\times$ over MPA and {pgz:.2f}$\\times$ over BPCS. "
    text += r'''Latency still grows with the batch because sampled data must be combined over the field and authentication paths must be traversed. The reduction in group work therefore does not imply constant proof-generation time. Yu et al.~\cite{YuTC25} retain faster proof generation by returning quotient coefficients, with the corresponding response and verification trade-offs shown in Fig.~\ref{fig:vi_communication} and Fig.~\ref{fig:vi_runtime_sweeps}(c).

\paragraph{Verification}
Fig.~\ref{fig:vi_runtime_sweeps}(c) shows that batching keeps verification close to MPA~\cite{XuTIFS26} while separating MultiAudit from the heavier checks of BPCS~\cite{ZhangTPDS23}, MKPDP~\cite{MiaoSCIS2026}, and the repeated per-file checks of Yu et al.~\cite{YuTC25}. The two witnesses permit one data MSM and two pairing terms, but the sampled tags still contribute work for every file. '''
    text += f"At forty files, verification is {vz:.2f}$\\times$ faster than BPCS. "
    text += r'''This gain reflects the complete verification equations, including tag authentication, rather than the opening normalization alone. The smaller gap to MPA is expected because both retain the leading sampled-tag MSM. Compact authentication reduces hashing overhead without eliminating that shared group work.

'''
    return text


def communication_analysis(saving):
    return (r'''\paragraph{Communication}
Fig.~\ref{fig:vi_communication} shows a substantially lower response-growth rate for MultiAudit than for the independent-path baselines. CMMs transmit overlapping authentication hashes once, while two aggregate witnesses replace the per-file witnesses of MPA~\cite{XuTIFS26}. Sampled tags and per-file evaluations remain in the response, so its size still grows with the batch. '''
            + f"At forty files, the measured mean encoded response is {saving:.1f}\\% smaller than MPA's native payload. "
            + r'''This saving mainly reflects compact authentication. The figure excludes framing for every scheme and uses expected CMM sizes, whereas the measured comparison includes MultiAudit framing and excludes baseline framing. BPCS~\cite{ZhangTPDS23} and MKPDP~\cite{MiaoSCIS2026} retain constant-size cryptographic responses, so the plotted communication advantage concerns Merkle-authenticated baselines.
''')


def sampling_analysis(source):
    label = r'\label{subsec:sampling_coverage}'
    start = source.index(label) + len(label)
    end = source.index(r'\subsection{', start)
    return source[start:end].strip()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=DEFAULT.parent)
    directory=parser.parse_args().directory
    source=ROOT/'paper/MultiAudit.tex';s=source.read_text()
    sampling=sampling_analysis(s)
    rows,meta=validate(directory/'runtime.csv')
    responses=validate_response(directory/'response.csv')
    base={name:{phase:next(float(r['milliseconds']) for r in rows if r['m']=='40' and r['scheme']==name and r['phase']==phase) for phase in ['Store','ProofGen','Verify']} for name in SCHEMES}
    f=base['MultiAudit'];wire=statistics.mean(int(r['wire_bytes']) for r in responses)
    xp=payload('XuTIFS26',40,3907,80,690);saving=100*(1-wire/xp)
    pg_ratio=base['ZhangTPDS23']['ProofGen']/f['ProofGen'];vr_ratio=base['ZhangTPDS23']['Verify']/f['Verify']
    xratio=base['XuTIFS26']['ProofGen']/f['ProofGen']
    method = cloud_setup()
    results = cloud_analysis(base).replace('MultiAudit', r'\MultiAudit{}')
    comm = communication_analysis(saving).replace('MultiAudit', r'\MultiAudit{}')
    sampling_heading=r'\subsection{Sampling Coverage and Parameter Selection}'+'\n'+r'\label{subsec:sampling_coverage}'+'\n'+'\n'
    phone_method=mobile_setup()
    phone_results=mobile_results(directory/'mobile')
    chain_method=onchain_setup()
    onchain=onchain_results(directory/'onchain')
    evaluation=('% BEGIN GENERATED EVALUATION\n'+r'\section{Evaluation}'+'\n'+r'\label{sec:evaluation}'+'\n'
                +method+'\n'+chain_method+'\n'+phone_method+'\n'+sampling_heading+sampling+'\n\n'
                +r'\subsection{Cloud Costs}'+'\n'+r'\label{subsec:cloud_costs}'+'\n'+runtime_figure(rows)+'\n'+results+communication_figure()+'\n'+comm+'\n'
                +r'\subsection{On-Chain Costs}'+'\n'+r'\label{subsec:onchain_costs}'+'\n'+onchain+'\n'
                +r'\subsection{Mobile User Costs}'+'\n'+r'\label{subsec:iphone_costs}'+'\n'+phone_results+'\n% END GENERATED EVALUATION')
    evaluation=merge_deployment_figures(format_algorithm_names(evaluation), load_mobile(directory/'mobile')['MultiAudit']['m'])
    a=s.index('% BEGIN GENERATED EVALUATION')
    marker=s.find('% END GENERATED EVALUATION',a)
    b=marker+len('% END GENERATED EVALUATION') if marker>=0 else s.index(r'\section{Conclusion}',a)
    s=s[:a]+evaluation+'\n\n'+s[b:]
    # The abstract is author-written and is preserved when experiments refresh.
    a=s.index(r'\label{fig:system model flowchar}');start=list(re.finditer(r'\\begin\{figure\*?\}',s[:a]))[-1].start();end=a+re.search(r'\\end\{figure\*?\}',s[a:]).end();figure1=s[start:end]
    assert hashlib.sha256(figure1.encode()).hexdigest()==json.loads((directory/'document.json').read_text())['figure1_sha256']
    s=s[:start]+'FIGUREONEPLACEHOLDER'+s[end:]
    s=re.sub(r'\n{3,}','\n\n',s).replace('FIGUREONEPLACEHOLDER',figure1)
    assert r'\input{' not in s and r'\includegraphics' not in s
    body=s.split(r'\begin{thebibliography}',1)[0]
    for mention in re.finditer(r'\bet(?:\s|~)+al\.',body):
        # A named construction can intervene, e.g. "Xu et al.'s MPA~\cite{...}".
        assert re.match(r"(?:'s)?[^.\n]{0,100}?\\cite(?:\[[^]]*\])?\{[^}]+\}",body[mention.end():])
    labels=re.findall(r'\\label\{([^}]+)\}',s);assert len(labels)==len(set(labels))
    assert evaluation.count(r'\subfloat[')==6 and evaluation.count(r'\begin{figure*}')==2 and evaluation.count(r'\begin{figure}')==0
    source.write_text(s+'\n')
    onchain_rows,onchain_meta=load_onchain(directory/'onchain')
    report={'scheme_name':'MultiAudit','measurement_key':'MultiAudit','fixtures':20,'online_audits':600,'response_measurements':30,'summary_rows':60,'baseline_ms':base,'mean_response_bytes':wire,'response_reduction_vs_xu_percent':saving,'figure_panels':['Store','ProofGen','Verify','Audit response','Total gas','Calldata gas','Mobile Store','Mobile Verify'],'communication_payload_MB':communication_payloads(),'evaluation_words':len(re.findall(r'\b\w+\b',method+phone_method+chain_method+sampling+results+phone_results+comm+onchain)),'evaluation_structure':['Experimental Setup','Sampling Coverage and Parameter Selection','Cloud Costs','On-Chain Costs','Mobile User Costs'],'mobile_comparison':load_mobile(directory/'mobile'),'onchain_comparison':{'measurement_source':onchain_meta['measurement_source'],'m_scan':onchain_meta['m_scan'],'s':80,'B_MB':10,'c':690,'audits_per_scheme_per_m':onchain_meta['audits_per_scheme_per_m'],'results':onchain_rows}}
    (directory/'publication.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()

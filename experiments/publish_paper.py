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
from onchain.report import load_results as load_onchain, latex_setup as onchain_setup, latex_results as onchain_results
from mobile_report import load_results as load_mobile, latex_setup as mobile_setup, latex_results as mobile_results, abstract_sentence as mobile_abstract

ROOT=Path(__file__).resolve().parents[1]
DISPLAY={'ZhangTPDS23':r'Zhang et al.~\cite{ZhangTPDS23}','MiaoSCIS2026':r'Miao et al.~\cite{MiaoSCIS2026}','XuTIFS26':r'Xu et al.~\cite{XuTIFS26}','MultiAudit':'MultiAudit','YuTC25':r'Yu et al.~\cite{YuTC25}'}
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
 if name=='MultiAudit':return (m*c+2*m+2)*G+2*m*32+m*expected_aux(n,c)*32
 if name=='XuTIFS26':return m*(32+(c+1)*G+c*L*32)
 if name=='YuTC25':return m*(s*32+(c+1)*G+c*L*32)
 if name=='ZhangTPDS23':return 3*G+32
 if name=='MiaoSCIS2026':return 2*G+32
 raise ValueError(name)

def analytical_example():
 m,s,c,n=40,80,690,3907;a=expected_aux(n,c)
 text=r'''\paragraph{Illustrative encoding-normalized comparison.}
For $(m,s,c,n)=(40,80,690,3907)$, assume 48-byte $\GG_1$ elements and 32-byte scalars and hashes. These are uniform encoding assumptions; Section~\ref{sec:evaluation} uses the backend's actual 64-byte group encodings. For a uniformly sampled $c$-subset of $[n]$ and a subtree $B$ containing $k_B$ real positions,
\[
\Pr[B\text{ touched}]=1-\frac{\binom{n-k_B}{c}}{\binom nc}.
\]
Summing these probabilities over internal subtrees and subtracting $c-1$, by the reconstruction count after Equation~\eqref{eq:aux_count}, gives '''+f'$\\mathbb E[|\\mathcal A_i(J)|]\\simeq{a:.2f}$ and $\\mathbb E[A_\\Sigma(J)]\\simeq{m*a:.2f}$. Actual response sizes depend on $J$.\n'
 text+=f"MultiAudit reduces server scalar terms from $3160E$ to $238E$ relative to {NAME['XuTIFS26']}, a {100*(1-238/3160):.1f}\\% reduction. The corresponding expected response reduction under this illustrative encoding is {100*(1-payload('MultiAudit',m,n,s,c,48)/payload('XuTIFS26',m,n,s,c,48)):.1f}\\%. Both protocols retain $\\mathcal O(mcs)$ field aggregation; measured latency also includes authentication, allocation and transcript work. {NAME['ZhangTPDS23']} and {NAME['MiaoSCIS2026']} retain constant-response advantages.\n\n"
 return text

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
    out += [r'\end{axis}',r'\end{tikzpicture}',r'\caption{Audit-response payload of Merkle-authenticated schemes at $B=10$~MB, $s=80$, and $c=690$. Native 64-byte groups and 32-byte scalars and hashes are used; MultiAudit uses expected CMM size. Framing is excluded. At $m=40$, MultiAudit reduces the expected payload by 71.9\% relative to Xu et al.~\cite{XuTIFS26}.}',r'\label{fig:vi_communication}',r'\end{figure}']
    return '\n'.join(out)


def runtime_figure(rows):
    out=[r'\begin{figure*}[!t]',r'\centering',legend_source()+r'\par\smallskip']
    for i,phase in enumerate(['Store','ProofGen','Verify']):
        caption=phase+(' (s)' if phase=='Store' else ' (ms)')
        out += [r'\subfloat['+caption+r']{\begin{minipage}{0.33\textwidth}\centering',plot_source(rows,phase),r'\end{minipage}}']
        if i<2:out.append(r'\hfill')
    out += [r'\caption{Runtime versus file count for $B=10$~MB per file, $s=80$, and $c=690$. Store is measured once in seconds on a logarithmic axis. Online bars show median milliseconds and interquartile ranges over 30 fresh audits.}',r'\label{fig:vi_runtime_sweeps}',r'\end{figure*}']
    return '\n'.join(out)


def sampling_analysis(source):
    start=source.index(r'\begin{lemma}[Sampling Coverage]')
    label=source.index(r'\label{rem:parameter_selection}',start)
    end=source.index(r'\end{remark}',label)+len(r'\end{remark}')
    return source[start:end]


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
    method=r'''\subsection{Experimental Setup}
We fix nominal 10~MB files (10,001,920 encoded bytes), $s=80$, $c=690$, and $n=3907$ for the multi-sector layout, with 64-byte $\GG_1$ elements and 32-byte scalars/hashes. Baseline normalization follows Tables~\ref{tab:computation} and~\ref{tab:communication}.

PC tests use Go~1.25.4 (\texttt{darwin/arm64}) on an Apple M4 (10 logical cores, 16~GiB RAM, macOS~26.5.2). All schemes share BN256 (go-ethereum~v1.17.2), Pippenger MSM, and field/storage kernels. We vary $m\in\{10,20,30,40\}$; '''+NAME['MiaoSCIS2026']+r''' uses two keywords per file and queries all files. All configurations use complete stored fixtures. Online calls use one worker and a locked OS thread; 30 fresh audits follow at least three warmups and five seconds of warmup. We report medians/interquartile ranges without sample removal. Store is measured once (up to four file workers for the searchable scheme, sequential otherwise). Setup, synthetic-input and challenge generation, response encoding, and transfer are excluded. GC is requested outside online timers; collections during calls remain included.
'''
    results=r'''\paragraph{Storage and scaling}
Fig.~\ref{fig:vi_runtime_sweeps}(a) shows approximately linear Store growth with file count. MultiAudit stays close to '''+NAME['XuTIFS26']+' and '+NAME['YuTC25']+r''', consistent with their common $mn\CompExp$ tag-generation term in Table~\ref{tab:computation}. Store still generates all chunk tags and complete per-file authentication trees. CMMs compact the sampled authentication paths during ProofGen, while coefficient aggregation reduces the opening-commitment work in that phase. Consequently, these improvements primarily benefit online auditing.

\paragraph{Proof generation}
Table~\ref{tab:computation} identifies the benefit of aggregating quotient coefficients before commitment: MultiAudit uses $[2(s-1)+2m]\CompExp$, replacing the $m(s-1)\CompExp$ witness term of '''+NAME['XuTIFS26']+r'''. Fig.~\ref{fig:vi_runtime_sweeps}(b) confirms lower proof-generation latency as the batch grows. '''+f"At $m=40$, the speedups are {xratio:.2f}$\\times$ over {NAME['XuTIFS26']} and {pg_ratio:.2f}$\\times$ over {NAME['ZhangTPDS23']}. "+r'''The latency gain is smaller than the scalar-term reduction because challenged-data aggregation remains $\mathcal O(mcs)$ and complete calls include field, authentication, and memory work. '''+NAME['YuTC25']+r''' retains faster ProofGen by returning quotient coefficients; Table~\ref{tab:communication} makes the corresponding response trade-off explicit.

\paragraph{Verification}
Fig.~\ref{fig:vi_runtime_sweeps}(c) is consistent with the verification terms in Table~\ref{tab:computation}: MultiAudit combines the openings into two pairing terms and one data MSM, while '''+NAME['YuTC25']+r''' repeats per-file checks and '''+NAME['ZhangTPDS23']+' and '+NAME['MiaoSCIS2026']+r''' have larger tag-related scalar terms. '''+f"The verification speedup over {NAME['ZhangTPDS23']} reaches {vr_ratio:.2f}$\\times$. "+r'''The latency of '''+NAME['XuTIFS26']+r''' remains close to MultiAudit's: both retain the leading $mc$ tag term, while MultiAudit additionally checks masks and binds its transcript. Group counts explain the trends but are not proportional latency predictions under MSM acceleration.

'''
    comm=r'''\paragraph{Communication}
Table~\ref{tab:communication} explains the reduction in Fig.~\ref{fig:vi_communication}: CMMs replace the $mcL$ independent-path hashes with $A_\Sigma(J)$ auxiliary hashes, and the opening component uses two witnesses. The full response still includes sampled tags and per-file masks. '''+f"At $m=40$, the mean encoded MultiAudit response is {saving:.1f}\\% smaller than the native payload accounting of {NAME['XuTIFS26']}. "+r'''This comparison includes MultiAudit framing and excludes baseline framing; the plotted estimates exclude framing for every scheme and use expected CMM sizes. '''+NAME['ZhangTPDS23']+' and '+NAME['MiaoSCIS2026']+r''' retain constant-size cryptographic responses, so MultiAudit's communication advantage concerns the Merkle-authenticated baselines rather than every comparison scheme.
'''
    sampling_heading=r'\subsection{Sampling Coverage and Parameter Selection}'+'\n'+r'\label{subsec:sampling_coverage}'+'\n'+r'The following calculation motivates the common challenge size.'+'\n\n'
    phone_method=mobile_setup()
    phone_results=mobile_results(directory/'mobile')
    chain_method=onchain_setup()
    onchain=onchain_results(directory/'onchain')
    evaluation=('% BEGIN GENERATED EVALUATION\n'+r'\section{Evaluation}'+'\n'+r'\label{sec:evaluation}'+'\n'
                +method+'\n'+chain_method+'\n'+phone_method+'\n'+sampling_heading+sampling+'\n\n'
                +r'\subsection{PC Results}'+'\n'+r'\label{subsec:pc_results}'+'\n'+runtime_figure(rows)+'\n'+results+communication_figure()+'\n'+comm+'\n'
                +r'\subsection{On-Chain Costs}'+'\n'+r'\label{subsec:onchain_costs}'+'\n'+onchain+'\n'
                +r'\subsection{iPhone Costs}'+'\n'+r'\label{subsec:iphone_costs}'+'\n'+phone_results+'\n% END GENERATED EVALUATION')
    a=s.index('% BEGIN GENERATED EVALUATION')
    marker=s.find('% END GENERATED EVALUATION',a)
    b=marker+len('% END GENERATED EVALUATION') if marker>=0 else s.index(r'\section{Conclusion}',a)
    s=s[:a]+evaluation+'\n\n'+s[b:]
    a=s.index(r'\paragraph{Illustrative encoding-normalized comparison.}');b=s.index('% BEGIN GENERATED EVALUATION',a);s=s[:a]+analytical_example()+s[b:]
    a=s.index(r'\begin{abstract}')+len(r'\begin{abstract}');b=s.index(r'\end{abstract}',a)
    abstract=s[a:b].split(' For $(m,B,s,c)=')[0].rstrip()
    abstract+=f" For $(m,B,s,c)=(40,10\\,\\mathrm{{MB}},80,690)$, MultiAudit achieves measured proof-generation and verification speedups of {pg_ratio:.2f}$\\times$ and {vr_ratio:.2f}$\\times$ relative to {NAME['ZhangTPDS23']}; its mean encoded response is {saving:.1f}\\% smaller than the native payload accounting of {NAME['XuTIFS26']}.\n"
    abstract=abstract.rstrip()+mobile_abstract(directory/'mobile')+'\n'
    s=s[:a]+abstract+s[b:]
    a=s.index(r'\label{fig:system model flowchar}');start=list(re.finditer(r'\\begin\{figure\*?\}',s[:a]))[-1].start();end=a+re.search(r'\\end\{figure\*?\}',s[a:]).end();figure1=s[start:end]
    assert hashlib.sha256(figure1.encode()).hexdigest()==json.loads((directory/'document.json').read_text())['figure1_sha256']
    s=s[:start]+'FIGUREONEPLACEHOLDER'+s[end:]
    s='\n'.join(line for line in s.splitlines() if not line.lstrip().startswith('%') or line.startswith(('% BEGIN GENERATED','% END GENERATED')))
    s=re.sub(r'\n{3,}','\n\n',s).replace('FIGUREONEPLACEHOLDER',figure1)
    assert r'\input{' not in s and r'\includegraphics' not in s
    body=s.split(r'\begin{thebibliography}',1)[0]
    for mention in re.finditer(r'\bet(?:\s|~)+al\.',body):
        assert re.match(r'\s*~?\\cite(?:\[[^]]*\])?\{[^}]+\}',body[mention.end():])
    labels=re.findall(r'\\label\{([^}]+)\}',s);assert len(labels)==len(set(labels))
    assert evaluation.count(r'\subfloat[')==3 and evaluation.count(r'\begin{figure*}')==1 and evaluation.count(r'\begin{figure}')==1
    source.write_text(s+'\n')
    onchain_rows,onchain_meta=load_onchain(directory/'onchain')
    report={'scheme_name':'MultiAudit','measurement_key':'MultiAudit','fixtures':20,'online_audits':600,'response_measurements':30,'summary_rows':60,'baseline_ms':base,'mean_response_bytes':wire,'response_reduction_vs_xu_percent':saving,'figure_panels':['Store','ProofGen','Verify','Audit response'],'communication_payload_MB':communication_payloads(),'evaluation_words':len(re.findall(r'\b\w+\b',method+phone_method+chain_method+sampling+results+phone_results+comm+onchain)),'evaluation_structure':['Experimental Setup','Sampling Coverage and Parameter Selection','PC Results','On-Chain Costs','iPhone Costs'],'mobile_comparison':load_mobile(directory/'mobile'),'onchain_comparison':{'measurement_source':onchain_meta['measurement_source'],'m':1,'s':80,'B_MB':10,'c':690,'audits_per_scheme':onchain_meta['audits_per_scheme'],'results':onchain_rows}}
    (directory/'publication.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()

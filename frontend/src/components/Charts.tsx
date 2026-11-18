import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { LanguageStat, Severity } from '../types'
import { SEVERITIES, SEV_COLOR } from '../utils/format'

const tooltipStyle = {
  contentStyle: { background: '#0e1429', border: '1px solid #25315f', borderRadius: 12, color: '#e2e8f0', fontSize: 12 },
  itemStyle: { color: '#e2e8f0' },
}

export function SeverityPie({ counts }: { counts: Record<Severity, number> }) {
  const data = SEVERITIES.map((s) => ({ name: s, value: counts[s] ?? 0 })).filter((d) => d.value > 0)
  const total = data.reduce((a, b) => a + b.value, 0)
  if (!total) return <p className="py-10 text-center text-sm text-slate-400">No findings to chart.</p>
  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative h-48 w-48 shrink-0">
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius={58} outerRadius={84} paddingAngle={2} stroke="none">
              {data.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name as Severity]} />)}
            </Pie>
            <Tooltip {...tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold text-white">{total}</span>
          <span className="text-[10px] uppercase tracking-wider text-slate-400">findings</span>
        </div>
      </div>
      <ul className="grid w-full grid-cols-2 gap-x-6 gap-y-2 text-sm">
        {SEVERITIES.map((s) => (
          <li key={s} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-2 capitalize text-slate-300"><i className="h-2.5 w-2.5 rounded-full" style={{ background: SEV_COLOR[s] }} />{s}</span>
            <b className="text-white">{counts[s] ?? 0}</b>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function LanguageBars({ languages }: { languages: LanguageStat[] }) {
  if (!languages.length) return <p className="py-10 text-center text-sm text-slate-400">No analysable languages found.</p>
  const data = languages.slice(0, 8).map((l) => ({ name: l.language, lines: l.lines, files: l.files, support: l.support }))
  return (
    <div style={{ height: Math.max(160, data.length * 38) }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
          <XAxis type="number" hide />
          <YAxis type="category" dataKey="name" width={92} tick={{ fill: '#cbd5e1', fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip {...tooltipStyle} cursor={{ fill: 'rgba(139,92,246,.08)' }}
            formatter={(v: number, _n, p) => [`${v} lines · ${(p.payload as any).files} files · ${(p.payload as any).support} support`, 'Size']} />
          <Bar dataKey="lines" radius={[0, 8, 8, 0]}>
            {data.map((d, i) => <Cell key={i} fill={d.support === 'full' ? '#8b5cf6' : '#22d3ee'} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function CategoryBars({ counts }: { counts: Record<string, number> }) {
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }))
  const colors: Record<string, string> = { Security: '#ff4d6d', 'Code Slop': '#a78bfa', 'Coding Gaps': '#f5c451', 'Loose Ends': '#22d3ee' }
  return (
    <div className="h-44">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 8 }}>
          <XAxis dataKey="name" tick={{ fill: '#cbd5e1', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis hide />
          <Tooltip {...tooltipStyle} cursor={{ fill: 'rgba(139,92,246,.08)' }} />
          <Bar dataKey="value" radius={[8, 8, 0, 0]}>
            {data.map((d) => <Cell key={d.name} fill={colors[d.name] ?? '#8b5cf6'} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

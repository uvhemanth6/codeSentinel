import { Link } from 'react-router-dom'

export function LogoMark({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <defs>
        <linearGradient id="cs-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#8b5cf6" />
          <stop offset="1" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
      <path d="M16 2 4 7v8c0 7.5 5 13 12 15 7-2 12-7.5 12-15V7z" fill="url(#cs-g)" />
      <path d="m11 16 4 4 7-8" stroke="#0b1020" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export default function Logo({ to = '/' }: { to?: string }) {
  return (
    <Link to={to} className="flex items-center gap-2.5 font-bold tracking-tight text-white">
      <LogoMark />
      <span className="text-lg">Code<span className="bg-gradient-to-r from-brand-400 to-accent-400 bg-clip-text text-transparent">Sentinel</span></span>
    </Link>
  )
}

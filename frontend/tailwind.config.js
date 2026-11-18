/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#060913', 900: '#0b1020', 850: '#0e1429', 800: '#121a35', 700: '#1a2447', 600: '#25315f', 500: '#34417a' },
        brand: { 300: '#c4b5fd', 400: '#a78bfa', 500: '#8b5cf6', 600: '#7c3aed' },
        accent: { 300: '#67e8f9', 400: '#22d3ee', 500: '#06b6d4' },
        sev: { critical: '#ff4d6d', high: '#ff8a4c', medium: '#f5c451', low: '#38bdf8', info: '#94a3b8' },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: { glow: '0 0 0 1px rgba(139,92,246,.25), 0 10px 40px -10px rgba(139,92,246,.35)' },
      keyframes: { fadeUp: { '0%': { opacity: 0, transform: 'translateY(8px)' }, '100%': { opacity: 1, transform: 'none' } } },
      animation: { fadeUp: 'fadeUp .35s ease-out both' },
    },
  },
  plugins: [],
}

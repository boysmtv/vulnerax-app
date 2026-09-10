/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html","./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: { 50:'#eef2ff', 500:'#6366f1', 600:'#4f46e5', 700:'#4338ca', 900:'#312e81' },
        critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#64748b'
      }
    }
  },
  plugins: []
}

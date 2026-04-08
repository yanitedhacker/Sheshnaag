/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  prefix: "tw-",
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Space Grotesk"', "Avenir Next", "Segoe UI", "sans-serif"],
      },
      colors: {
        shesh: {
          ink: "#f3efe8",
          muted: "#c8bbb0",
          panel: "rgba(24, 20, 18, 0.94)",
          card: "rgba(36, 29, 25, 0.88)",
          line: "rgba(255, 255, 255, 0.08)",
          accent: "#d9783a",
          accent2: "#7bb597",
        },
      },
      boxShadow: {
        panel: "0 24px 64px rgba(5, 4, 3, 0.45)",
      },
    },
  },
  plugins: [],
  corePlugins: {
    preflight: false,
  },
};

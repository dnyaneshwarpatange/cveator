import type { CSSProperties } from "react";

const paths = {
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z M8.5 12l2.5 2.5 4.5-5",
  grid: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  bell: "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4",
  software: "M3 4h18v13H3z M8 21h8 M12 17v4",
  card: "M3 5h18v14H3z M3 10h18 M7 15h3",
  arrow: "M5 12h14 M13 6l6 6-6 6",
  search: "M20 20l-5-5 M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0",
  plus: "M12 5v14 M5 12h14",
  check: "M5 12l4 4L19 6",
  close: "m6 6 12 12 M18 6 6 18",
  refresh: "M20 7v5h-5 M4 17v-5h5 M5 8a8 8 0 0 1 13-3l2 2 M19 16a8 8 0 0 1-13 3l-2-2",
  external: "M14 3h7v7 M21 3 10 14 M10 3H3v18h18v-7",
  logout: "M9 3H3v18h6 M10 12h11 M17 8l4 4-4 4",
  warning: "m12 3 10 18H2L12 3Z M12 9v5 M12 17v.1",
  chevron: "m9 5 7 7-7 7",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0"
};

export function Icon({ name, size = 20, className, style }: {
  name: keyof typeof paths; size?: number; className?: string; style?: CSSProperties;
}) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"
    className={className} style={style}><path d={paths[name]} /></svg>;
}

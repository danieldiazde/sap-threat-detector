export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;

export const COLORS = {
  bg: '#0a0a0f',
  panel: '#111118',
  cyan: '#00d4ff',
  orange: '#ff6b35',
  green: '#00ff88',
  purple: '#a855f7',
  blue: '#3b82f6',
  pink: '#ec4899',
  red: '#ef4444',
  gray: '#6b7280',
  white: '#ffffff',
  card: '#1a1a2e',
};

export const FONTS = {
  heading: '"Inter", sans-serif',
  mono: '"JetBrains Mono", monospace',
};

export const SCENES: Record<number, number> = {
  1: 40, 2: 40, 3: 40, 4: 40, 5: 40,
  6: 40, 7: 30, 8: 30, 9: 10,
};

export const PEOPLE: Record<number, { name: string; role: string; color: string }> = {
  1: { name: 'Persona 1', role: 'AI & ML Engineer',    color: '#a855f7' },
  2: { name: 'Persona 2', role: 'Cloud Integration',   color: '#3b82f6' },
  3: { name: 'Persona 3', role: 'Project Manager',     color: '#ff6b35' },
  4: { name: 'Persona 4', role: 'Frontend Engineer',   color: '#ec4899' },
  5: { name: 'Persona 5', role: 'Backend Engineer',    color: '#00d4ff' },
};

export const SCENE_PERSON: Record<number, number | null> = {
  1: 3, 2: 3, 3: 1, 4: 1, 5: 2, 6: 5, 7: 4, 8: 3, 9: null,
};

// frontend/src/theme.js  (chart colors and design tokens, mirrors theme.css)

export const SEVERITY_META = {
  CRITICAL: {
    label: 'CRITICAL',
    color: '#E5484D',
    bg: 'rgba(229, 72, 77, 0.10)',
    border: 'rgba(229, 72, 77, 0.30)',
    weight: 4,
  },
  HIGH: {
    label: 'HIGH',
    color: '#F76B15',
    bg: 'rgba(247, 107, 21, 0.10)',
    border: 'rgba(247, 107, 21, 0.28)',
    weight: 3,
  },
  MEDIUM: {
    label: 'MEDIUM',
    color: '#E5A93C',
    bg: 'rgba(229, 169, 60, 0.10)',
    border: 'rgba(229, 169, 60, 0.28)',
    weight: 2,
  },
  LOW: {
    label: 'LOW',
    color: '#3B82F6',
    bg: 'rgba(59, 130, 246, 0.10)',
    border: 'rgba(59, 130, 246, 0.28)',
    weight: 1,
  },
};

// Also export case-tolerant lookup
SEVERITY_META.Critical = SEVERITY_META.CRITICAL;
SEVERITY_META.High = SEVERITY_META.HIGH;
SEVERITY_META.Medium = SEVERITY_META.MEDIUM;
SEVERITY_META.Low = SEVERITY_META.LOW;

export const COLORS = {
  bg: '#08090B',
  surface: '#0E1014',
  surface2: '#14171D',
  border: '#1E232C',
  borderHover: '#2E3543',
  text: '#F0F2F5',
  muted: '#8A93A2',
  subtle: '#525B6A',
  accent: '#3B82F6',
  accent2: '#14B8A6',
  accentPurple: '#8B5CF6',
  grid: '#1E232C',
  severity: {
    Critical: '#E5484D',
    High: '#F76B15',
    Medium: '#E5A93C',
    Low: '#3B82F6',
    CRITICAL: '#E5484D',
    HIGH: '#F76B15',
    MEDIUM: '#E5A93C',
    LOW: '#3B82F6',
  },
};

export const PIE_COLORS = [
  '#3B82F6',
  '#14B8A6',
  '#E5A93C',
  '#E5484D',
  '#8B5CF6',
  '#F76B15',
  '#2EB872',
  '#EC4899',
];


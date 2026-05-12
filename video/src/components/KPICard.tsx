import React from 'react';
import { interpolate } from 'remotion';
import { COLORS, FONTS } from '../constants';

interface KPICardProps {
  label: string;
  value: number;
  unit?: string;
  color: string;
  icon: string;
  appearFrame: number;
  currentFrame: number;
}

export const KPICard: React.FC<KPICardProps> = ({
  label,
  value,
  unit,
  color,
  icon,
  appearFrame,
  currentFrame,
}) => {
  const progress = interpolate(
    currentFrame,
    [appearFrame, appearFrame + 20],
    [0, 1],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  const translateY = interpolate(
    currentFrame,
    [appearFrame, appearFrame + 20],
    [40, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  const countedValue = Math.round(
    interpolate(
      currentFrame,
      [appearFrame, appearFrame + 30],
      [0, value],
      { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
    ),
  );

  return (
    <div
      style={{
        width: 200,
        height: 120,
        background: COLORS.card,
        borderTop: `3px solid ${color}`,
        borderRadius: '0 0 8px 8px',
        padding: '16px 18px',
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        opacity: progress,
        transform: `translateY(${translateY}px)`,
        fontFamily: FONTS.heading,
      }}
    >
      <span style={{ fontSize: 24 }}>{icon}</span>
      <span style={{ fontSize: 12, color: COLORS.gray }}>{label}</span>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
        <span style={{ fontSize: 32, fontWeight: 800, color: COLORS.white }}>
          {countedValue}
        </span>
        {unit && (
          <span style={{ fontSize: 14, color: COLORS.gray }}>{unit}</span>
        )}
      </div>
    </div>
  );
};

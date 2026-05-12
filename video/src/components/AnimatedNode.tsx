import React from 'react';
import { interpolate, spring } from 'remotion';
import { COLORS, FONTS } from '../constants';

interface AnimatedNodeProps {
  label: string;
  sublabel?: string;
  color: string;
  icon: string;
  appearFrame: number;
  currentFrame: number;
  width?: number;
  height?: number;
  style?: React.CSSProperties;
}

export const AnimatedNode: React.FC<AnimatedNodeProps> = ({
  label,
  sublabel,
  color,
  icon,
  appearFrame,
  currentFrame,
  width = 160,
  height = 80,
  style,
}) => {
  const progress = Math.max(0, Math.min(1, spring({
    frame: currentFrame - appearFrame,
    fps: 30,
    config: { damping: 14, stiffness: 120 },
  })));

  const glowIntensity = 0.3 + 0.15 * Math.sin(currentFrame * 0.05);
  const glowColor = color + Math.round(glowIntensity * 255).toString(16).padStart(2, '0');

  return (
    <div
      style={{
        width,
        height,
        borderRadius: 10,
        background: COLORS.card,
        border: `2px solid ${color}`,
        boxShadow: `0 0 20px ${glowColor}`,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 2,
        transform: `scale(${progress})`,
        opacity: progress,
        fontFamily: FONTS.heading,
        padding: '8px 12px',
        ...style,
      }}
    >
      <span style={{ fontSize: 18 }}>{icon}</span>
      <span style={{ fontSize: 13, fontWeight: 700, color: COLORS.white, textAlign: 'center' }}>
        {label}
      </span>
      {sublabel && (
        <span style={{ fontSize: 10, color: COLORS.gray, textAlign: 'center' }}>
          {sublabel}
        </span>
      )}
    </div>
  );
};

import React from 'react';
import { interpolate } from 'remotion';
import { COLORS, FONTS } from '../constants';

interface AnimatedArrowProps {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  color: string;
  appearFrame: number;
  currentFrame: number;
  label?: string;
}

export const AnimatedArrow: React.FC<AnimatedArrowProps> = ({
  x1, y1, x2, y2, color, appearFrame, currentFrame, label,
}) => {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const length = Math.sqrt(dx * dx + dy * dy);

  const dashOffset = interpolate(
    currentFrame,
    [appearFrame, appearFrame + 20],
    [length, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  const labelOpacity = interpolate(
    currentFrame,
    [appearFrame + 20, appearFrame + 30],
    [0, 1],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  const midX = (x1 + x2) / 2;
  const midY = (y1 + y2) / 2;
  const markerId = `arrow-${x1}-${y1}-${x2}-${y2}`.replace(/\./g, '_');

  return (
    <g>
      <defs>
        <marker
          id={markerId}
          markerWidth="8"
          markerHeight="8"
          refX="6"
          refY="3"
          orient="auto"
        >
          <path d="M0,0 L0,6 L8,3 z" fill={color} />
        </marker>
      </defs>
      <line
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        stroke={color}
        strokeWidth={2}
        strokeDasharray={length}
        strokeDashoffset={dashOffset}
        markerEnd={`url(#${markerId})`}
      />
      {label && (
        <text
          x={midX}
          y={midY - 8}
          textAnchor="middle"
          fill={COLORS.gray}
          fontSize={10}
          fontFamily={FONTS.heading}
          opacity={labelOpacity}
        >
          {label}
        </text>
      )}
    </g>
  );
};

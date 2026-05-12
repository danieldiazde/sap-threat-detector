import React, { useEffect, useRef, useState } from 'react';
import { interpolate } from 'remotion';

interface AnimatedLineProps {
  path: string;
  color: string;
  appearFrame: number;
  currentFrame: number;
  strokeWidth?: number;
}

export const AnimatedLine: React.FC<AnimatedLineProps> = ({
  path,
  color,
  appearFrame,
  currentFrame,
  strokeWidth = 2,
}) => {
  const pathRef = useRef<SVGPathElement>(null);
  const [length, setLength] = useState(0);

  useEffect(() => {
    if (pathRef.current) {
      setLength(pathRef.current.getTotalLength());
    }
  }, [path]);

  const dashOffset = interpolate(
    currentFrame,
    [appearFrame, appearFrame + 30],
    [length, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  return (
    <path
      ref={pathRef}
      d={path}
      stroke={color}
      strokeWidth={strokeWidth}
      fill="none"
      strokeDasharray={length}
      strokeDashoffset={dashOffset}
    />
  );
};

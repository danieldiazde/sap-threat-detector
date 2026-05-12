import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';

const StatCard: React.FC<{
  icon: string;
  number: string;
  unit: string;
  label: string;
  borderColor: string;
  appearFrame: number;
  frame: number;
}> = ({ icon, number, unit, label, borderColor, appearFrame, frame }) => {
  const progress = interpolate(frame, [appearFrame, appearFrame + 25], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const translateY = interpolate(frame, [appearFrame, appearFrame + 25], [60, 0], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <div
      style={{
        width: 300,
        padding: '28px 24px',
        background: COLORS.card,
        borderRadius: 12,
        borderLeft: `4px solid ${borderColor}`,
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        opacity: progress,
        transform: `translateY(${translateY}px)`,
        fontFamily: FONTS.heading,
      }}
    >
      <span style={{ fontSize: 32 }}>{icon}</span>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{ fontSize: 40, fontWeight: 800, color: COLORS.white }}>{number}</span>
        {unit && <span style={{ fontSize: 18, color: COLORS.gray }}>{unit}</span>}
      </div>
      <span style={{ fontSize: 13, color: COLORS.gray, lineHeight: 1.5 }}>{label}</span>
    </div>
  );
};

export const Scene1Intro: React.FC = () => {
  const frame = useCurrentFrame();

  const line1Opacity = interpolate(frame, [0, 20], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const line2Opacity = interpolate(frame, [20, 50], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const bottomOpacity = interpolate(frame, [300, 400], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '60px 64px',
        gap: 48,
      }}
    >
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontSize: 38,
            fontWeight: 700,
            color: COLORS.white,
            textAlign: 'center',
            opacity: line1Opacity,
          }}
        >
          ¿Qué pasa cuando un ataque ocurre en SAP...
        </span>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontSize: 38,
            fontWeight: 700,
            color: COLORS.cyan,
            textAlign: 'center',
            opacity: line2Opacity,
          }}
        >
          ...y nadie lo detecta a tiempo?
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'row', gap: 28 }}>
        <StatCard
          icon="🔴"
          number="287"
          unit="días"
          label="tiempo promedio para detectar una brecha"
          borderColor={COLORS.red}
          appearFrame={80}
          frame={frame}
        />
        <StatCard
          icon="⚡"
          number="$4.45M"
          unit="USD"
          label="costo promedio por incidente de seguridad"
          borderColor={COLORS.orange}
          appearFrame={120}
          frame={frame}
        />
        <StatCard
          icon="🎯"
          number="43%"
          unit=""
          label="de ataques apuntan a infraestructura ERP"
          borderColor={COLORS.purple}
          appearFrame={160}
          frame={frame}
        />
      </div>

      <span
        style={{
          fontFamily: FONTS.heading,
          fontSize: 20,
          fontWeight: 500,
          color: COLORS.gray,
          opacity: bottomOpacity,
          textAlign: 'center',
        }}
      >
        Nosotros lo detectamos en milisegundos.
      </span>
    </AbsoluteFill>
  );
};

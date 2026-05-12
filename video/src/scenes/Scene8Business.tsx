import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';

const cards = [
  {
    icon: '⏱',
    headline: '245ms de MTTD',
    color: COLORS.cyan,
    body: 'vs. 287 días del promedio\nde la industria',
    sub: 'Reducción del 99.9998%',
    appear: 60,
  },
  {
    icon: '🛡',
    headline: 'Detección sin etiquetas',
    color: COLORS.orange,
    body: 'Modelo no supervisado —\nno requiere ataques previos',
    sub: 'Isolation Forest + DBSCAN',
    appear: 110,
  },
  {
    icon: '☁',
    headline: 'Nativo en BTP',
    color: COLORS.green,
    body: 'Corre en el ecosistema SAP —\ncero fricción de integración',
    sub: 'HANA · Webhook · Cloud Foundry',
    appear: 160,
  },
];

export const Scene8Business: React.FC = () => {
  const frame = useCurrentFrame();

  const titleY = interpolate(frame, [0, 30], [-40, 0], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const titleOpacity = interpolate(frame, [0, 30], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const line1Opacity = interpolate(frame, [500, 530], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const line2Opacity = interpolate(frame, [530, 560], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const footnoteOpacity = interpolate(frame, [700, 730], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '50px 60px', gap: 40 }}>
      <div
        style={{
          opacity: titleOpacity,
          transform: `translateY(${titleY}px)`,
          fontFamily: FONTS.heading,
          fontWeight: 800,
          fontSize: 38,
          color: COLORS.white,
          textAlign: 'center',
        }}
      >
        ¿Qué significa esto para SAP?
      </div>

      <div style={{ display: 'flex', flexDirection: 'row', gap: 24 }}>
        {cards.map((card, i) => {
          const scale = Math.min(spring({ frame: frame - card.appear, fps: 30, config: { damping: 14, stiffness: 120 } }), 1);
          return (
            <div
              key={i}
              style={{
                width: 320,
                padding: '24px',
                background: COLORS.card,
                borderLeft: `4px solid ${card.color}`,
                borderRadius: '0 12px 12px 0',
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
                transform: `scale(${scale})`,
                opacity: scale,
                fontFamily: FONTS.heading,
              }}
            >
              <span style={{ fontSize: 36 }}>{card.icon}</span>
              <span style={{ fontSize: 24, fontWeight: 700, color: card.color }}>{card.headline}</span>
              <span style={{ fontSize: 15, color: COLORS.white, whiteSpace: 'pre-line', lineHeight: 1.6 }}>
                {card.body}
              </span>
              <span style={{ fontSize: 12, color: COLORS.gray }}>{card.sub}</span>
            </div>
          );
        })}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, marginTop: 16 }}>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 700,
            fontSize: 32,
            color: COLORS.white,
            opacity: line1Opacity,
          }}
        >
          Menos tiempo detectando.
        </span>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 700,
            fontSize: 32,
            color: COLORS.cyan,
            opacity: line2Opacity,
          }}
        >
          Más tiempo respondiendo.
        </span>
      </div>

      <span
        style={{
          fontFamily: FONTS.heading,
          fontSize: 13,
          color: COLORS.gray,
          opacity: footnoteOpacity,
          position: 'absolute',
          bottom: 50,
        }}
      >
        TEC × SAP Hackathon · Mayo 2025
      </span>
    </AbsoluteFill>
  );
};

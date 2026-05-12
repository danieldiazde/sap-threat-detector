import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';
import { AnimatedNode } from '../components/AnimatedNode';
import { AnimatedArrow } from '../components/AnimatedArrow';

const W = 812; // 65% of 1248px left panel width approx
const H = 1080;

const nodes = {
  SAP_API:   { x: 120,  y: 340, color: COLORS.orange, icon: '📡', label: 'SAP API',    sub: 'CSV / REST',        appear: 0   },
  PIPELINE:  { x: 400,  y: 340, color: COLORS.cyan,   icon: '⚙️', label: 'FastAPI',     sub: 'Pipeline asyncio',  appear: 40  },
  MODEL:     { x: 680,  y: 340, color: COLORS.purple,  icon: '🤖', label: 'ML Model',   sub: 'Isolation Forest',  appear: 80  },
  HANA:      { x: 960,  y: 200, color: COLORS.blue,    icon: '🗄', label: 'SAP HANA',   sub: 'Cloud DB',          appear: 100 },
  WEBHOOK:   { x: 960,  y: 340, color: COLORS.green,   icon: '📡', label: 'Webhook',    sub: 'SAP Alerting',      appear: 140 },
  DASHBOARD: { x: 960,  y: 480, color: COLORS.pink,    icon: '📊', label: 'Dashboard',  sub: 'Streamlit SOC',     appear: 180 },
};

type NodeKey = keyof typeof nodes;

const arrows: { from: NodeKey; to: NodeKey; appear: number }[] = [
  { from: 'SAP_API',  to: 'PIPELINE',  appear: 20  },
  { from: 'PIPELINE', to: 'MODEL',     appear: 60  },
  { from: 'MODEL',    to: 'HANA',      appear: 100 },
  { from: 'MODEL',    to: 'WEBHOOK',   appear: 140 },
  { from: 'MODEL',    to: 'DASHBOARD', appear: 180 },
];

export const Scene2Architecture: React.FC = () => {
  const frame = useCurrentFrame();

  const bottomOpacity = interpolate(frame, [400, 440], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const dotPeriod = 60;
  const dotProgress = (frame - 300) % dotPeriod;
  const showDot = frame >= 300;

  const p = nodes.PIPELINE;
  const h = nodes.HANA;
  const dotX = interpolate(dotProgress, [0, dotPeriod], [p.x + 80, h.x - 80], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const dotY = interpolate(dotProgress, [0, dotPeriod], [p.y, h.y], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill style={{ position: 'relative' }}>
      <svg
        style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
        viewBox={`0 0 ${W} ${H}`}
      >
        {arrows.map((a, i) => {
          const fn = nodes[a.from];
          const tn = nodes[a.to];
          return (
            <AnimatedArrow
              key={i}
              x1={fn.x + 80}
              y1={fn.y}
              x2={tn.x - 80}
              y2={tn.y}
              color={fn.color}
              appearFrame={a.appear}
              currentFrame={frame}
            />
          );
        })}
        {showDot && (
          <circle cx={dotX} cy={dotY} r={5} fill={COLORS.cyan} opacity={0.9}>
            <animate attributeName="opacity" values="0.6;1;0.6" dur="0.5s" repeatCount="indefinite" />
          </circle>
        )}
      </svg>

      {(Object.keys(nodes) as NodeKey[]).map((key) => {
        const n = nodes[key];
        return (
          <div
            key={key}
            style={{
              position: 'absolute',
              left: (n.x / W) * 100 + '%',
              top: (n.y / H) * 100 + '%',
              transform: 'translate(-50%, -50%)',
            }}
          >
            <AnimatedNode
              label={n.label}
              sublabel={n.sub}
              color={n.color}
              icon={n.icon}
              appearFrame={n.appear}
              currentFrame={frame}
              width={160}
              height={80}
            />
          </div>
        );
      })}

      <div
        style={{
          position: 'absolute',
          bottom: 60,
          left: 0,
          right: 0,
          display: 'flex',
          justifyContent: 'center',
          opacity: bottomOpacity,
        }}
      >
        <span
          style={{
            fontFamily: FONTS.heading,
            fontSize: 16,
            color: COLORS.green,
            background: COLORS.green + '22',
            border: `1px solid ${COLORS.green}`,
            borderRadius: 100,
            padding: '8px 20px',
          }}
        >
          🟢&nbsp;&nbsp;Sistema corriendo en SAP BTP · 24/7
        </span>
      </div>
    </AbsoluteFill>
  );
};

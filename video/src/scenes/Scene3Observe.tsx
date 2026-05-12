import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';
import { AnimatedNode } from '../components/AnimatedNode';
import { AnimatedArrow } from '../components/AnimatedArrow';

const flowNodes = [
  { label: 'SAP API',           sub: 'Source',          color: COLORS.orange, icon: '📡', appear: 30,  x: 80  },
  { label: 'sap_log_fetcher.py', sub: 'async fetch',     color: COLORS.cyan,   icon: '📥', appear: 70,  x: 300 },
  { label: 'log_parser.py',      sub: 'normalize',       color: COLORS.purple, icon: '🔬', appear: 110, x: 530 },
  { label: 'DataFrame',          sub: 'validated schema', color: COLORS.green,  icon: '📋', appear: 150, x: 760 },
];

const arrowDefs = [
  { appear: 50,  label: 'async · paginado · cada 30s' },
  { appear: 90,  label: 'normaliza columnas' },
  { appear: 130, label: 'valida schema' },
];

const logRows = [
  { ts: '2025-05-12 10:00:01', ip: '10.0.0.1',     event: 'LOGIN_OK',   status: '200', time: '45ms',  highlight: false },
  { ts: '2025-05-12 10:00:03', ip: '10.0.0.2',     event: 'GET /api',   status: '200', time: '32ms',  highlight: false },
  { ts: '2025-05-12 10:00:04', ip: '192.168.4.77', event: 'POST /auth', status: '403', time: '12ms',  highlight: true  },
  { ts: '2025-05-12 10:00:04', ip: '192.168.4.77', event: 'POST /auth', status: '403', time: '11ms',  highlight: true  },
  { ts: '2025-05-12 10:00:05', ip: '192.168.4.77', event: 'POST /auth', status: '403', time: '10ms',  highlight: true  },
];

export const Scene3Observe: React.FC = () => {
  const frame = useCurrentFrame();

  const labelOpacity = interpolate(frame, [0, 15], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const tableOpacity = interpolate(frame, [200, 230], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const tableTranslate = interpolate(frame, [200, 230], [30, 0], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const badgeOpacity = interpolate(frame, [700, 730], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill style={{ padding: '50px 50px', display: 'flex', flexDirection: 'column', gap: 32 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, opacity: labelOpacity }}>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 800,
            fontSize: 28,
            color: COLORS.cyan,
            borderBottom: `3px solid ${COLORS.cyan}`,
            paddingBottom: 4,
          }}
        >
          OBSERVE
        </span>
        <span style={{ fontFamily: FONTS.heading, fontSize: 16, color: COLORS.gray }}>
          Ingesta de Logs
        </span>
      </div>

      <div style={{ position: 'relative', height: 120 }}>
        <svg
          style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
          viewBox="0 0 950 120"
        >
          {arrowDefs.map((a, i) => (
            <AnimatedArrow
              key={i}
              x1={flowNodes[i].x + 80}
              y1={60}
              x2={flowNodes[i + 1].x - 0}
              y2={60}
              color={flowNodes[i].color}
              appearFrame={a.appear}
              currentFrame={frame}
              label={a.label}
            />
          ))}
        </svg>
        {flowNodes.map((n, i) => (
          <div
            key={i}
            style={{
              position: 'absolute',
              left: n.x,
              top: 20,
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
        ))}
      </div>

      <div
        style={{
          opacity: tableOpacity,
          transform: `translateY(${tableTranslate}px)`,
          fontFamily: FONTS.mono,
          fontSize: 13,
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '220px 160px 140px 80px 80px',
            gap: 0,
            borderBottom: `1px solid ${COLORS.gray}33`,
            paddingBottom: 8,
            marginBottom: 4,
          }}
        >
          {['datetime', 'source_ip', 'event_type', 'status', 'resp_time'].map((h) => (
            <span key={h} style={{ color: COLORS.cyan, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              {h}
            </span>
          ))}
        </div>
        {logRows.map((row, i) => {
          const rowOpacity = interpolate(frame, [200 + i * 25, 200 + i * 25 + 15], [0, 1], {
            extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
          });
          return (
            <div
              key={i}
              style={{
                display: 'grid',
                gridTemplateColumns: '220px 160px 140px 80px 80px',
                gap: 0,
                padding: '7px 8px',
                opacity: rowOpacity,
                background: row.highlight ? COLORS.orange + '26' : 'transparent',
                borderLeft: row.highlight ? `3px solid ${COLORS.orange}` : '3px solid transparent',
                borderRadius: 4,
                marginBottom: 2,
              }}
            >
              <span style={{ color: COLORS.gray }}>{row.ts}</span>
              <span style={{ color: row.highlight ? COLORS.orange : COLORS.white }}>{row.ip}</span>
              <span style={{ color: COLORS.white }}>{row.event}</span>
              <span style={{ color: row.status === '403' ? COLORS.red : COLORS.green }}>{row.status}</span>
              <span style={{ color: COLORS.gray }}>{row.time}</span>
            </div>
          );
        })}
      </div>

      <div
        style={{
          opacity: badgeOpacity,
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <span
          style={{
            fontFamily: FONTS.heading,
            fontSize: 15,
            color: COLORS.green,
            background: COLORS.green + '26',
            border: `1px solid ${COLORS.green}`,
            borderRadius: 100,
            padding: '8px 20px',
          }}
        >
          📥&nbsp;&nbsp;Logs ingeridos y normalizados · latencia &lt; 200ms
        </span>
      </div>
    </AbsoluteFill>
  );
};

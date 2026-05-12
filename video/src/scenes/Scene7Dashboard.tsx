import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';
import { KPICard } from '../components/KPICard';

const barHeights = [20, 45, 30, 80, 120, 95];
const barLabels = ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00'];

const linePoints = [0.1, 0.05, 0.12, 0.08, -0.3, -0.82, -0.75, -0.9];

const logRows = [
  { ts: '15:02:11', ip: '192.168.4.77', score: '-0.82', sev: 'ALTA',  sevColor: COLORS.red,    estado: '✅ Alertado' },
  { ts: '15:01:44', ip: '10.0.1.23',    score: '-0.61', sev: 'MEDIA', sevColor: COLORS.orange,  estado: '✅ Alertado' },
  { ts: '15:00:59', ip: '172.16.0.5',   score: '-0.31', sev: 'BAJA',  sevColor: '#eab308',      estado: '🔍 Monitored' },
];

export const Scene7Dashboard: React.FC = () => {
  const frame = useCurrentFrame();

  const maxBarH = 120;
  const barAnimH = (h: number, i: number) =>
    interpolate(frame, [200 + i * 5, 260 + i * 5], [0, h], {
      extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
    });

  // Line chart
  const chartW = 280;
  const chartH = 120;
  const normalizeY = (v: number) => ((v + 1) / 1.5) * chartH;
  const drawProgress = interpolate(frame, [200, 280], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const visiblePoints = Math.floor(drawProgress * linePoints.length);
  const polylinePoints = linePoints
    .slice(0, Math.max(2, visiblePoints))
    .map((v, i) => `${(i / (linePoints.length - 1)) * chartW},${chartH - normalizeY(v)}`)
    .join(' ');

  const thresholdY = chartH - normalizeY(-0.5);

  const tableOpacity = interpolate(frame, [400, 430], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const blink = Math.floor(frame / 30) % 2 === 0;

  return (
    <AbsoluteFill style={{ display: 'flex', flexDirection: 'column', fontSize: 13 }}>
      {/* Top bar */}
      <div
        style={{
          background: '#0d0d14',
          borderBottom: `1px solid ${COLORS.card}`,
          padding: '10px 20px',
          fontFamily: FONTS.heading,
          fontSize: 15,
          color: COLORS.white,
          flexShrink: 0,
        }}
      >
        🛡 TPs_data — Security Operations Center
      </div>

      {/* KPI row */}
      <div style={{ display: 'flex', flexDirection: 'row', gap: 16, padding: '16px 20px', flexShrink: 0 }}>
        <KPICard label="MTTD p50" value={245} unit="ms" color={COLORS.green} icon="⚡" appearFrame={0} currentFrame={frame} />
        <KPICard label="MTTD p95" value={380} unit="ms" color={COLORS.orange} icon="⏱" appearFrame={30} currentFrame={frame} />
        <KPICard label="Amenazas detectadas" value={12} color={COLORS.red} icon="🎯" appearFrame={60} currentFrame={frame} />
        <KPICard label="Alertas enviadas" value={9} color={COLORS.cyan} icon="📡" appearFrame={90} currentFrame={frame} />
      </div>

      {/* Charts row */}
      <div style={{ display: 'flex', flexDirection: 'row', gap: 20, padding: '0 20px', flex: 1, minHeight: 0 }}>
        {/* Bar chart */}
        <div
          style={{
            flex: 1,
            background: COLORS.card,
            borderRadius: 10,
            padding: 16,
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
            opacity: interpolate(frame, [200, 220], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }),
          }}
        >
          <span style={{ fontFamily: FONTS.heading, fontSize: 13, color: COLORS.gray, marginBottom: 4 }}>
            Anomalías por hora
          </span>
          <svg viewBox={`0 0 280 ${maxBarH + 20}`} style={{ flex: 1 }}>
            {barHeights.map((h, i) => {
              const bh = barAnimH(h, i);
              const bx = i * 46 + 8;
              return (
                <g key={i}>
                  <rect
                    x={bx}
                    y={maxBarH - bh}
                    width={36}
                    height={bh}
                    fill={i === barHeights.length - 1 ? COLORS.red : COLORS.cyan + '99'}
                    rx={3}
                  />
                  <text x={bx + 18} y={maxBarH + 14} textAnchor="middle" fill={COLORS.gray} fontSize={9} fontFamily={FONTS.heading}>
                    {barLabels[i]}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Line chart */}
        <div
          style={{
            flex: 1,
            background: COLORS.card,
            borderRadius: 10,
            padding: 16,
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
            opacity: interpolate(frame, [200, 220], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }),
          }}
        >
          <span style={{ fontFamily: FONTS.heading, fontSize: 13, color: COLORS.gray, marginBottom: 4 }}>
            Score de anomalía
          </span>
          <svg viewBox={`0 0 ${chartW} ${chartH + 20}`} style={{ flex: 1 }}>
            <line
              x1={0} y1={thresholdY}
              x2={chartW} y2={thresholdY}
              stroke={COLORS.orange}
              strokeWidth={1}
              strokeDasharray="4 4"
            />
            <text x={chartW - 4} y={thresholdY - 4} textAnchor="end" fill={COLORS.orange} fontSize={9} fontFamily={FONTS.heading}>
              Umbral
            </text>
            <polyline
              points={polylinePoints}
              fill="none"
              stroke={COLORS.cyan}
              strokeWidth={2}
            />
            {linePoints.slice(0, Math.max(0, visiblePoints)).map((v, i) => (
              <circle
                key={i}
                cx={(i / (linePoints.length - 1)) * chartW}
                cy={chartH - normalizeY(v)}
                r={4}
                fill={v < -0.5 ? COLORS.red : COLORS.cyan}
              />
            ))}
          </svg>
        </div>
      </div>

      {/* Log table */}
      <div style={{ padding: '12px 20px 16px', opacity: tableOpacity, fontFamily: FONTS.mono }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '120px 160px 80px 100px 140px',
            borderBottom: `1px solid ${COLORS.gray}33`,
            paddingBottom: 6,
            marginBottom: 4,
          }}
        >
          {['Timestamp', 'IP', 'Score', 'Severidad', 'Estado'].map((h) => (
            <span key={h} style={{ fontSize: 10, color: COLORS.cyan, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              {h}
            </span>
          ))}
        </div>
        {logRows.map((row, i) => (
          <div
            key={i}
            style={{
              display: 'grid',
              gridTemplateColumns: '120px 160px 80px 100px 140px',
              padding: '5px 4px',
              alignItems: 'center',
            }}
          >
            <span style={{ color: COLORS.gray, fontSize: 12 }}>{row.ts}</span>
            <span style={{ color: COLORS.white, fontSize: 12 }}>{row.ip}</span>
            <span style={{ color: row.score === '-0.82' ? COLORS.red : COLORS.orange, fontSize: 12 }}>{row.score}</span>
            <span
              style={{
                fontSize: 10,
                color: row.sevColor,
                background: row.sevColor + '33',
                border: `1px solid ${row.sevColor}`,
                borderRadius: 100,
                padding: '2px 8px',
                display: 'inline-block',
                width: 'fit-content',
              }}
            >
              {row.sev}
            </span>
            <span style={{ color: COLORS.gray, fontSize: 12 }}>
              {row.estado}
              {i === logRows.length - 1 && (
                <span style={{ color: COLORS.cyan, opacity: blink ? 1 : 0 }}>▮</span>
              )}
            </span>
          </div>
        ))}
      </div>
    </AbsoluteFill>
  );
};

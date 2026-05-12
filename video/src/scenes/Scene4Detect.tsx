import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';

const features = [
  { name: 'total_requests',      value: '847',    badge: null },
  { name: 'unique_endpoints',    value: '1',      badge: null },
  { name: 'avg_response_time',   value: '11ms',   badge: null },
  { name: 'error_rate',          value: '0.73',   badge: { text: '⚠️ Alto',    color: COLORS.orange } },
  { name: 'brute_force_score',   value: '0.91',   badge: { text: '🔴 Crítico', color: COLORS.red    } },
  { name: 'request_rate_zscore', value: '4.2σ',   badge: { text: '🔴 Crítico', color: COLORS.red    } },
];

export const Scene4Detect: React.FC = () => {
  const frame = useCurrentFrame();

  const detectLabelOpacity = interpolate(frame, [220, 240], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const scoreRaw = interpolate(frame, [260, 320], [0, -0.82], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const scoreColor = scoreRaw > -0.5
    ? COLORS.green
    : scoreRaw > -0.7
    ? COLORS.orange
    : COLORS.red;

  const thresholdOpacity = interpolate(frame, [360, 380], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const dotPos = interpolate(frame, [360, 390], [0, 82], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const alertScale = spring({
    frame: frame - 480,
    fps: 30,
    config: { damping: 14, stiffness: 120 },
  });

  const shake = frame >= 480 && frame < 490
    ? Math.sin((frame - 480) * 1.8) * 3
    : 0;

  const dividerWidth = interpolate(frame, [200, 230], [0, 100], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill style={{ display: 'flex', flexDirection: 'row' }}>
      {/* LEFT: ANALYZE */}
      <div style={{ flex: 1, padding: '50px 40px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 800,
            fontSize: 28,
            color: COLORS.cyan,
            borderBottom: `3px solid ${COLORS.cyan}`,
            paddingBottom: 4,
            opacity: interpolate(frame, [0, 15], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }),
          }}
        >
          ANALYZE
        </span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 8 }}>
          {features.map((f, i) => {
            const featureOpacity = interpolate(frame, [30 + i * 25, 30 + i * 25 + 15], [0, 1], {
              extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
            });
            return (
              <div key={f.name} style={{ display: 'flex', alignItems: 'center', gap: 10, opacity: featureOpacity }}>
                <span style={{ fontFamily: FONTS.mono, fontSize: 14, color: COLORS.gray, width: 200 }}>
                  {f.name}
                </span>
                <span style={{ color: COLORS.gray, fontSize: 14 }}>→</span>
                <span style={{ fontFamily: FONTS.mono, fontSize: 16, fontWeight: 700, color: COLORS.white }}>
                  {f.value}
                </span>
                {f.badge && (
                  <span
                    style={{
                      fontFamily: FONTS.heading,
                      fontSize: 11,
                      color: f.badge.color,
                      background: f.badge.color + '33',
                      border: `1px solid ${f.badge.color}`,
                      borderRadius: 100,
                      padding: '2px 10px',
                    }}
                  >
                    {f.badge.text}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        <div
          style={{
            height: 1,
            background: `linear-gradient(to right, transparent, ${COLORS.gray}66, transparent)`,
            width: dividerWidth + '%',
            marginTop: 16,
          }}
        />
      </div>

      {/* RIGHT: DETECT */}
      <div style={{ flex: 1, padding: '50px 40px', display: 'flex', flexDirection: 'column', gap: 24 }}>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 800,
            fontSize: 28,
            color: COLORS.orange,
            borderBottom: `3px solid ${COLORS.orange}`,
            paddingBottom: 4,
            opacity: detectLabelOpacity,
          }}
        >
          DETECT
        </span>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span
            style={{
              fontFamily: FONTS.heading,
              fontWeight: 800,
              fontSize: 72,
              color: scoreColor,
              textShadow: `0 0 20px ${scoreColor}66`,
              opacity: interpolate(frame, [260, 275], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }),
            }}
          >
            {scoreRaw.toFixed(2)}
          </span>
          <span style={{ fontFamily: FONTS.heading, fontSize: 14, color: COLORS.gray }}>
            Isolation Forest score
          </span>
        </div>

        <div style={{ opacity: thresholdOpacity, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ position: 'relative', width: 300 }}>
            <div style={{ height: 8, borderRadius: 4, overflow: 'hidden', display: 'flex' }}>
              <div style={{ width: '60%', background: COLORS.green }} />
              <div style={{ width: '40%', background: COLORS.red }} />
            </div>
            <div
              style={{
                position: 'absolute',
                left: '60%',
                top: -20,
                transform: 'translateX(-50%)',
                fontSize: 11,
                color: COLORS.orange,
                fontFamily: FONTS.heading,
                whiteSpace: 'nowrap',
              }}
            >
              Umbral: -0.50
            </div>
            <div
              style={{
                position: 'absolute',
                left: '60%',
                top: 0,
                height: 8,
                width: 2,
                background: COLORS.orange,
              }}
            />
            <div
              style={{
                position: 'absolute',
                left: dotPos + '%',
                top: -4,
                transform: 'translateX(-50%)',
              }}
            >
              <div
                style={{
                  width: 16,
                  height: 16,
                  borderRadius: 8,
                  background: COLORS.red,
                  boxShadow: `0 0 8px ${COLORS.red}`,
                }}
              />
              <div
                style={{
                  position: 'absolute',
                  left: '50%',
                  top: 18,
                  transform: 'translateX(-50%)',
                  fontSize: 11,
                  color: COLORS.red,
                  fontFamily: FONTS.heading,
                  whiteSpace: 'nowrap',
                }}
              >
                -0.82
              </div>
            </div>
          </div>
        </div>

        <div
          style={{
            transform: `scale(${Math.min(alertScale, 1)}) translateX(${shake}px)`,
            opacity: Math.min(alertScale, 1),
            background: COLORS.red + '33',
            border: `2px solid ${COLORS.red}`,
            borderRadius: 12,
            padding: '16px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
            alignSelf: 'flex-start',
          }}
        >
          <span style={{ fontFamily: FONTS.heading, fontSize: 18, fontWeight: 700, color: COLORS.red }}>
            🚨&nbsp;&nbsp;ANOMALÍA DETECTADA
          </span>
          <span style={{ fontFamily: FONTS.heading, fontSize: 14, color: COLORS.white }}>
            Severidad: ALTA · IP: 192.168.4.77
          </span>
        </div>
      </div>
    </AbsoluteFill>
  );
};

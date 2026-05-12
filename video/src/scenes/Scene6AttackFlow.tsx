import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';

const steps = [
  { frame: 80,  dot: COLORS.red,  ts: 't+0ms',   text: 'IP 192.168.4.77 detectada — 847 req en 30s' },
  { frame: 160, dot: COLORS.cyan, ts: 't+45ms',  text: 'Logs ingeridos → DataFrame (fetch + parse)' },
  { frame: 240, dot: COLORS.purple, ts: 't+112ms', text: 'Features extraídas — error_rate: 0.73 · brute_force: 0.91' },
  { frame: 320, dot: COLORS.orange, ts: 't+180ms', text: 'Isolation Forest score: -0.82 (umbral: -0.50)' },
  { frame: 400, dot: COLORS.cyan, ts: 't+195ms', text: 'Anomalía detectada — ALTA severidad' },
  { frame: 480, dot: COLORS.gray,  ts: 't+210ms', text: 'Incident Report → reports/incidents/INC-001.md' },
  { frame: 560, dot: COLORS.green, ts: 't+228ms', text: 'Webhook disparado → SAP Alerting' },
  { frame: 640, dot: COLORS.blue,  ts: 't+241ms', text: 'Guardado en SAP HANA → tabla ANOMALIES' },
];

const stepIcons = ['🔴', '📥', '🔬', '🤖', '🚨', '📋', '📡', '💾'];

export const Scene6AttackFlow: React.FC = () => {
  const frame = useCurrentFrame();

  const lineHeight = interpolate(frame, [0, 200], [0, 640], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const progressWidth = interpolate(frame, [80, 640], [0, 100], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const mttdScale = spring({ frame: frame - 750, fps: 30, config: { damping: 14, stiffness: 120 } });

  return (
    <AbsoluteFill style={{ padding: '40px 50px', display: 'flex', flexDirection: 'column', gap: 0 }}>
      {/* Progress bar top */}
      <div style={{ height: 4, background: '#1a1a2e', borderRadius: 2, marginBottom: 24, overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            width: progressWidth + '%',
            background: COLORS.cyan,
            borderRadius: 2,
          }}
        />
      </div>

      <div style={{ flex: 1, position: 'relative', display: 'flex', flexDirection: 'row' }}>
        {/* Vertical timeline line */}
        <div style={{ position: 'relative', width: 40, marginRight: 0 }}>
          <div
            style={{
              position: 'absolute',
              left: 19,
              top: 0,
              width: 2,
              height: lineHeight,
              background: COLORS.gray + '55',
            }}
          />
        </div>

        {/* Steps */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 0 }}>
          {steps.map((step, i) => {
            const slideIn = interpolate(frame, [step.frame, step.frame + 20], [0, 1], {
              extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
            });
            const translateX = interpolate(frame, [step.frame, step.frame + 20], [30, 0], {
              extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
            });

            return (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 16,
                  opacity: slideIn,
                  transform: `translateX(${translateX}px)`,
                  marginBottom: 10,
                  position: 'relative',
                }}
              >
                {/* Dot on timeline */}
                <div
                  style={{
                    position: 'absolute',
                    left: -32,
                    width: 12,
                    height: 12,
                    borderRadius: 6,
                    background: step.dot,
                    boxShadow: `0 0 8px ${step.dot}`,
                    flexShrink: 0,
                  }}
                />
                {/* Connector */}
                <div style={{ width: 20, height: 1, background: COLORS.gray + '44' }} />
                {/* Icon */}
                <span style={{ fontSize: 18, flexShrink: 0 }}>{stepIcons[i]}</span>
                {/* Timestamp */}
                <span
                  style={{
                    fontFamily: FONTS.mono,
                    fontSize: 13,
                    color: COLORS.cyan,
                    width: 80,
                    flexShrink: 0,
                  }}
                >
                  {step.ts}
                </span>
                {/* Text */}
                <span style={{ fontFamily: FONTS.heading, fontSize: 15, color: COLORS.white }}>
                  {step.text}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* MTTD final */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          transform: `scale(${Math.min(mttdScale, 1)})`,
          opacity: Math.min(mttdScale, 1),
          marginTop: 16,
        }}
      >
        <span style={{ fontFamily: FONTS.heading, fontSize: 16, color: COLORS.gray }}>
          MTTD Pipeline:
        </span>
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 800,
            fontSize: 72,
            color: COLORS.green,
            textShadow: `0 0 30px ${COLORS.green}`,
          }}
        >
          245ms
        </span>
        <span style={{ fontFamily: FONTS.heading, fontSize: 14, color: COLORS.gray }}>
          vs. 287 días del promedio de la industria
        </span>
      </div>
    </AbsoluteFill>
  );
};

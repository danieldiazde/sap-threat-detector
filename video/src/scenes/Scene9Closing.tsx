import React, { useEffect, useRef } from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame } from 'remotion';
import { COLORS, FONTS, PEOPLE } from '../constants';

export const Scene9Closing: React.FC = () => {
  const frame = useCurrentFrame();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const particles = Array.from({ length: 80 }, () => ({
      x: Math.random() * 1920,
      y: Math.random() * 1080,
      r: 1.5 + Math.random() * 1.5,
      speed: 0.3 + Math.random() * 0.4,
      opacity: 0.3 + Math.random() * 0.3,
    }));

    let animId: number;
    const tick = () => {
      ctx.clearRect(0, 0, 1920, 1080);
      particles.forEach((p) => {
        p.y -= p.speed;
        p.opacity -= 0.001;
        if (p.y < 0 || p.opacity <= 0) {
          p.y = 1080;
          p.x = Math.random() * 1920;
          p.opacity = 0.3 + Math.random() * 0.3;
        }
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${p.opacity})`;
        ctx.fill();
      });
      animId = requestAnimationFrame(tick);
    };
    tick();
    return () => cancelAnimationFrame(animId);
  }, []);

  const logoScale = interpolate(frame, [0, 30], [0.8, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const logoOpacity = interpolate(frame, [0, 30], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const cardsOpacity = interpolate(frame, [60, 80], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const subOpacity = interpolate(frame, [220, 245], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const sub2Opacity = interpolate(frame, [260, 280], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const personOrder = [1, 2, 3, 4, 5];

  return (
    <AbsoluteFill style={{ background: COLORS.bg, position: 'relative' }}>
      <canvas
        ref={canvasRef}
        width={1920}
        height={1080}
        style={{ position: 'absolute', top: 0, left: 0, zIndex: 0 }}
      />
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100%',
          gap: 48,
        }}
      >
        <span
          style={{
            fontFamily: FONTS.heading,
            fontWeight: 800,
            fontSize: 80,
            color: COLORS.white,
            textShadow: `0 0 40px ${COLORS.white}66`,
            transform: `scale(${logoScale})`,
            opacity: logoOpacity,
            letterSpacing: '-0.02em',
          }}
        >
          TPs_data
        </span>

        <div
          style={{
            display: 'flex',
            flexDirection: 'row',
            gap: 24,
            opacity: cardsOpacity,
          }}
        >
          {personOrder.map((id, i) => {
            const person = PEOPLE[id];
            const cardScale = Math.min(
              spring({ frame: frame - (60 + i * 25), fps: 30, config: { damping: 14, stiffness: 120 } }),
              1,
            );
            return (
              <div
                key={id}
                style={{
                  width: 220,
                  height: 140,
                  background: COLORS.card,
                  borderRadius: 12,
                  border: `2px solid ${person.color}`,
                  boxShadow: `0 0 20px ${person.color}4d`,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 12,
                  transform: `scale(${cardScale})`,
                  opacity: cardScale,
                  fontFamily: FONTS.heading,
                }}
              >
                <span style={{ fontSize: 16, fontWeight: 700, color: COLORS.white }}>
                  {person.name}
                </span>
                <span
                  style={{
                    fontSize: 11,
                    color: person.color,
                    background: person.color + '33',
                    border: `1px solid ${person.color}`,
                    borderRadius: 100,
                    padding: '3px 12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em',
                  }}
                >
                  {person.role}
                </span>
              </div>
            );
          })}
        </div>

        <span
          style={{
            fontFamily: FONTS.heading,
            fontSize: 16,
            color: COLORS.gray,
            opacity: subOpacity,
          }}
        >
          TEC × SAP Hackathon · 2025
        </span>

        <span
          style={{
            fontFamily: FONTS.heading,
            fontSize: 14,
            color: COLORS.cyan,
            opacity: sub2Opacity,
          }}
        >
          SAP AI Security — Threat Detector
        </span>
      </div>
    </AbsoluteFill>
  );
};

import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';
import { AnimatedNode } from '../components/AnimatedNode';
import { AnimatedArrow } from '../components/AnimatedArrow';

export const Scene5Cloud: React.FC = () => {
  const frame = useCurrentFrame();

  const containerOpacity = interpolate(frame, [0, 20], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const badge1Opacity = interpolate(frame, [500, 520], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const badge2Opacity = interpolate(frame, [600, 620], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  const dotPeriod = 90;
  const dotProgress = Math.max(0, (frame - 300)) % dotPeriod;
  const showDot = frame >= 300;

  // BTP container: centered in left panel (812px wide, 1080px tall)
  const btpLeft = 156;
  const btpTop = 390;
  const btpW = 500;
  const btpH = 300;

  // External nodes
  const sapApiX = 30;
  const sapApiY = 540;
  const hanaX = 720;
  const hanaY = 440;
  const webhookX = 720;
  const webhookY = 540;
  const dashX = 340;
  const dashY = 760;

  // Inside BTP nodes
  const fastApiX = btpLeft + 60;
  const fastApiY = btpTop + 120;
  const asyncioX = btpLeft + 210;
  const asyncioY = btpTop + 120;
  const mlX = btpLeft + 360;
  const mlY = btpTop + 120;

  const dotX = interpolate(dotProgress, [0, dotPeriod], [btpLeft + 420, webhookX], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const dotY = interpolate(dotProgress, [0, dotPeriod], [btpTop + 120, webhookY], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill style={{ position: 'relative' }}>
      {/* BTP Container rect */}
      <div
        style={{
          position: 'absolute',
          left: btpLeft,
          top: btpTop,
          width: btpW,
          height: btpH,
          border: `2px solid ${COLORS.blue}`,
          background: COLORS.blue + '0d',
          borderRadius: 16,
          opacity: containerOpacity,
        }}
      >
        <span
          style={{
            position: 'absolute',
            top: 10,
            left: 16,
            fontFamily: FONTS.heading,
            fontSize: 14,
            fontWeight: 700,
            color: COLORS.blue,
          }}
        >
          SAP BTP Cloud Foundry
        </span>
      </div>

      {/* SVG arrows */}
      <svg
        style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
        viewBox="0 0 812 1080"
      >
        <AnimatedArrow x1={sapApiX + 80} y1={sapApiY} x2={btpLeft} y2={fastApiY} color={COLORS.orange} appearFrame={200} currentFrame={frame} />
        <AnimatedArrow x1={mlX + 80} y1={mlY} x2={hanaX} y2={hanaY} color={COLORS.blue} appearFrame={240} currentFrame={frame} />
        <AnimatedArrow x1={mlX + 80} y1={mlY + 20} x2={webhookX} y2={webhookY} color={COLORS.green} appearFrame={270} currentFrame={frame} />
        <AnimatedArrow x1={asyncioX + 80} y1={btpTop + btpH} x2={dashX} y2={dashY} color={COLORS.pink} appearFrame={300} currentFrame={frame} />
        {showDot && (
          <circle cx={dotX} cy={dotY} r={5} fill={COLORS.green}>
            <animate attributeName="opacity" values="0.6;1;0.6" dur="0.4s" repeatCount="indefinite" />
          </circle>
        )}
      </svg>

      {/* Inside BTP nodes */}
      <div style={{ position: 'absolute', left: fastApiX, top: fastApiY - 40 }}>
        <AnimatedNode label="FastAPI App" sublabel="" color={COLORS.cyan} icon="⚡" appearFrame={40} currentFrame={frame} width={140} height={70} />
      </div>
      <div style={{ position: 'absolute', left: asyncioX, top: asyncioY - 40 }}>
        <AnimatedNode label="asyncio Pipeline" sublabel="" color={COLORS.purple} icon="🔄" appearFrame={80} currentFrame={frame} width={140} height={70} />
      </div>
      <div style={{ position: 'absolute', left: mlX, top: mlY - 40 }}>
        <AnimatedNode label="ML Model" sublabel="" color={COLORS.purple} icon="🤖" appearFrame={120} currentFrame={frame} width={140} height={70} />
      </div>

      {/* External nodes */}
      <div style={{ position: 'absolute', left: sapApiX, top: sapApiY - 40 }}>
        <AnimatedNode label="SAP API" sublabel="" color={COLORS.orange} icon="📡" appearFrame={150} currentFrame={frame} width={140} height={70} />
      </div>
      <div style={{ position: 'absolute', left: hanaX, top: hanaY - 40 }}>
        <AnimatedNode label="SAP HANA Cloud" sublabel="" color={COLORS.blue} icon="🗄" appearFrame={190} currentFrame={frame} width={150} height={70} />
      </div>
      <div style={{ position: 'absolute', left: webhookX, top: webhookY - 40 }}>
        <AnimatedNode label="SAP Webhook" sublabel="" color={COLORS.green} icon="📡" appearFrame={230} currentFrame={frame} width={140} height={70} />
      </div>
      <div style={{ position: 'absolute', left: dashX - 70, top: dashY - 40 }}>
        <AnimatedNode label="Dashboard" sublabel="" color={COLORS.pink} icon="📊" appearFrame={270} currentFrame={frame} width={140} height={70} />
      </div>

      {/* Badges */}
      <div
        style={{
          position: 'absolute',
          bottom: 110,
          left: 0,
          right: 0,
          display: 'flex',
          justifyContent: 'center',
          opacity: badge1Opacity,
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
          ✅&nbsp;&nbsp;Live en SAP BTP · deploy May 4, 2025
        </span>
      </div>
      <div
        style={{
          position: 'absolute',
          bottom: 70,
          left: 0,
          right: 0,
          display: 'flex',
          justifyContent: 'center',
          opacity: badge2Opacity,
        }}
      >
        <span
          style={{
            fontFamily: FONTS.mono,
            fontSize: 13,
            color: COLORS.gray,
          }}
        >
          /health ✓&nbsp;&nbsp;/ready ✓&nbsp;&nbsp;/metrics ✓
        </span>
      </div>
    </AbsoluteFill>
  );
};

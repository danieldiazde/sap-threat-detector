import React from 'react';
import { useCurrentFrame } from 'remotion';
import { COLORS, FONTS } from '../constants';
import { PersonPanel } from './PersonPanel';

interface SplitScreenProps {
  leftContent: React.ReactNode;
  sceneNumber: number;
  showPerson?: boolean;
  personId: number | null;
  children?: React.ReactNode;
}

export const SplitScreen: React.FC<SplitScreenProps> = ({
  leftContent,
  sceneNumber,
  showPerson = true,
  personId,
  children,
}) => {
  const frame = useCurrentFrame();
  const content = leftContent ?? children;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'row',
        width: '100%',
        height: '100%',
        background: COLORS.bg,
        fontFamily: FONTS.heading,
      }}
    >
      <div
        style={{
          width: showPerson ? '65%' : '100%',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {content}
        <div
          style={{
            position: 'absolute',
            bottom: 24,
            left: 28,
            fontFamily: FONTS.heading,
            fontSize: 13,
            color: COLORS.gray,
            letterSpacing: '0.08em',
          }}
        >
          0{sceneNumber} / 09
        </div>
        <div
          style={{
            position: 'absolute',
            top: 20,
            right: 24,
            fontFamily: FONTS.heading,
            fontWeight: 700,
            fontSize: 14,
            color: COLORS.white,
            opacity: 0.4,
            letterSpacing: '0.1em',
          }}
        >
          TPs_data
        </div>
      </div>
      {showPerson && (
        <div
          style={{
            width: '35%',
            background: COLORS.panel,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <PersonPanel personId={personId} frame={frame} />
        </div>
      )}
    </div>
  );
};

import React from 'react';
import { Composition } from 'remotion';
import { loadFont as loadInter } from '@remotion/google-fonts/Inter';
import { loadFont as loadJetBrains } from '@remotion/google-fonts/JetBrainsMono';
import { MainVideo } from './MainVideo';
import { FPS, WIDTH, HEIGHT } from './constants';

loadInter();
loadJetBrains();

export const Root: React.FC = () => {
  return (
    <Composition
      id="MainVideo"
      component={MainVideo}
      durationInFrames={9300}
      fps={FPS}
      width={WIDTH}
      height={HEIGHT}
    />
  );
};

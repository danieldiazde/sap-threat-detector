import { Sequence } from 'remotion';
import { SCENES, SCENE_PERSON, FPS } from './constants';
import { SplitScreen } from './components/SplitScreen';
import { Scene1Intro } from './scenes/Scene1Intro';
import { Scene2Architecture } from './scenes/Scene2Architecture';
import { Scene3Observe } from './scenes/Scene3Observe';
import { Scene4Detect } from './scenes/Scene4Detect';
import { Scene5Cloud } from './scenes/Scene5Cloud';
import { Scene6AttackFlow } from './scenes/Scene6AttackFlow';
import { Scene7Dashboard } from './scenes/Scene7Dashboard';
import { Scene8Business } from './scenes/Scene8Business';
import { Scene9Closing } from './scenes/Scene9Closing';

const sceneComponents = [
  Scene1Intro,
  Scene2Architecture,
  Scene3Observe,
  Scene4Detect,
  Scene5Cloud,
  Scene6AttackFlow,
  Scene7Dashboard,
  Scene8Business,
];

export const MainVideo: React.FC = () => {
  const offsets: number[] = [];
  let cumulative = 0;
  for (let i = 1; i <= 9; i++) {
    offsets.push(cumulative * FPS);
    cumulative += SCENES[i];
  }

  return (
    <>
      {sceneComponents.map((SceneComponent, idx) => {
        const sceneNum = idx + 1;
        const personId = SCENE_PERSON[sceneNum];
        const durationInFrames = SCENES[sceneNum] * FPS;
        return (
          <Sequence key={sceneNum} from={offsets[idx]} durationInFrames={durationInFrames}>
            <SplitScreen sceneNumber={sceneNum} showPerson personId={personId} leftContent={<SceneComponent />} />
          </Sequence>
        );
      })}
      <Sequence from={offsets[8]} durationInFrames={SCENES[9] * FPS}>
        <Scene9Closing />
      </Sequence>
    </>
  );
};

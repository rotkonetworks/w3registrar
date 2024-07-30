// components/ChallengeList.tsx
import { Component, For } from 'solid-js';
import { Challenge } from '../types';
import Input from './Input';

interface ChallengeListProps {
  challenges: Challenge[];
}

const ChallengeList: Component<ChallengeListProps> = (props) => (
  <div class="mt-8 text-center">
    <h2 class="text-2xl font-bold">Challenge</h2>
    <p class="text-sm text-gray-500">{props.challenges.filter(c => c.completed).length}/{props.challenges.length}</p>
    <div class="space-y-2 mt-4">
      <For each={props.challenges}>
        {(challenge) => (
          <div class={`flex items-center justify-between p-2 rounded-md ${challenge.completed ? 'bg-green-200' : 'bg-yellow-200'}`}>
            <Input readonly value={challenge.value} class="bg-transparent border-none" />
            <button class="text-blue-600 hover:text-blue-800">Copy</button>
          </div>
        )}
      </For>
    </div>
  </div>
);

export default ChallengeList;

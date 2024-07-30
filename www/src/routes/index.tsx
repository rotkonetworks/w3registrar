import { Component } from 'solid-js';
import Card from '~/components/Card';
import IdentityForm from '~/components/IdentityForm';
import ChallengeList from '~/components/ChallengeList';
import { appData } from '~/data';

const MainContent: Component = () => (
  <div class="flex justify-center items-center min-h-screen bg-gray-100">
    <Card>
      <Card.Header title={appData.timer} subtitle={appData.user} />
      <Card.Content>
        <IdentityForm fields={appData.identityFields} />
        <ChallengeList challenges={appData.challenges} />
      </Card.Content>
    </Card>
  </div>
);

export default function Registrar() {
  return (
    <main>
      <h1 class="sr-only">W3REG Identity Challenge</h1>
      <MainContent />
    </main>
  );
}

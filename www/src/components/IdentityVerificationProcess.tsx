import React, { useState, useEffect } from 'react';
import Header from './Header';
import ProgressBar from './ProgressBar';
import IdentityForm from './IdentityForm';
import ChallengeVerification from './ChallengeVerification';
import CompletionPage from './CompletionPage';
//import { Identity, Challenges } from './types';

const IdentityVerificationProcess = () => {
  const [stage, setStage] = useState(0);
  const [network, setNetwork] = useState('Polkadot');
  const [identity, setIdentity] = useState({
    displayName: '',
    matrix: '',
    email: '',
    discord: '',
    twitter: ''
  });
  const [challenges, setChallenges] = useState({
    displayName: false,
    matrix: { value: '', verified: false },
    email: { value: '', verified: false },
    discord: { value: '', verified: false },
    twitter: { value: '', verified: false }
  });
  const [error, setError] = useState('');

  const handleSubmitIdentity = () => {
    if (identity.displayName.trim() === '') {
      setError('Display Name is required');
      return;
    }
    setStage(1);
    setChallenges(prev => ({
      displayName: true,
      ...Object.entries(identity).reduce((acc, [key, value]) => {
        if (key !== 'displayName' && value.trim() !== '') {
          acc[key] = { value: Math.random().toString(36).substring(2, 10), verified: false };
        }
        return acc;
      }, {} as typeof prev)
    }));
  };

  const handleVerifyChallenge = (key) => {
    setChallenges(prev => ({
      ...prev,
      [key]: { ...prev[key], verified: true }
    }));
  };

  const handleCancel = () => {
    setStage(0);
    setChallenges({
      displayName: false,
      matrix: { value: '', verified: false },
      email: { value: '', verified: false },
      discord: { value: '', verified: false },
      twitter: { value: '', verified: false }
    });
  };

  const handleProceed = () => {
    setStage(2);
  };

  const handleSelectAccount = (account) => {
    console.log(`Selected account: ${account}`);
    // Implement account selection logic here
  };

  const handleRemoveIdentity = () => {
    console.log('Removing identity');
    // Implement identity removal logic here
  };

  const handleLogout = () => {
    console.log('Logging out');
    // Implement logout logic here
  };

  const renderStage = () => {
    switch(stage) {
      case 0:
        return <IdentityForm
          identity={identity}
          setIdentity={setIdentity}
          onSubmit={handleSubmitIdentity}
          error={error}
        />;
      case 1:
        return <ChallengeVerification
          identity={identity}
          challenges={challenges}
          onVerify={handleVerifyChallenge}
          onCancel={handleCancel}
          onProceed={handleProceed}
        />;
      case 2:
        return <CompletionPage />;
      default:
        return null;
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto p-6 bg-white border border-stone-300">
      <Header
        displayName={identity.displayName}
        network={network}
        setNetwork={setNetwork}
        onSelectAccount={handleSelectAccount}
        onRemoveIdentity={handleRemoveIdentity}
        onLogout={handleLogout}
      />
      <ProgressBar progress={stage === 0 ? 0 : stage === 1 ? 50 : 100} />
      {renderStage()}
    </div>
  );
};

export default IdentityVerificationProcess;

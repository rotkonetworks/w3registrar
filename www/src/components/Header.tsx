import React from 'react';
import UserDropdown from './UserDropdown';
import NetworkDropdown from './NetworkDropdown';

const Header = ({ displayName, network, setNetwork, onSelectAccount, onRemoveIdentity, onLogout }) => (
  <div className="flex justify-between items-center mb-6">
    <UserDropdown
      displayName={displayName}
      onSelectAccount={onSelectAccount}
      onRemoveIdentity={onRemoveIdentity}
      onLogout={onLogout}
    />
    <NetworkDropdown network={network} setNetwork={setNetwork} />
  </div>
);

export default Header;

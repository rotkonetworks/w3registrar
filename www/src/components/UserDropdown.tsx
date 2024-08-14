import React, { useState, useEffect } from 'react';

const UserDropdown = ({ displayName, onSelectAccount, onRemoveIdentity, onLogout }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isAccountsOpen, setIsAccountsOpen] = useState(false);

  // testing for fetched from an API or passed as a prop
  const accounts = Array.from({ length: 100 }, (_, i) => `Account ${i + 1}`);

  return (
    <div className="relative">
      <button 
        onClick={() => setIsOpen(!isOpen)} 
        className="bg-stone-200 text-stone-800 px-3 py-1 text-sm font-medium border border-stone-400 w-full text-left"
      >
        {displayName || 'User'} ▼
      </button>
      {isOpen && (
        <div className="absolute left-0 mt-1 w-48 bg-white border border-stone-300 shadow-lg z-10">
          <button
            className="block w-full text-left px-4 py-2 text-sm text-stone-700 hover:bg-stone-100"
            onClick={() => setIsAccountsOpen(!isAccountsOpen)}
          >
            Select Account ▶
          </button>
          <button
            className="block w-full text-left px-4 py-2 text-sm text-stone-700 hover:bg-stone-100"
            onClick={onRemoveIdentity}
          >
            Remove Identity
          </button>
          <button
            className="block w-full text-left px-4 py-2 text-sm text-stone-700 hover:bg-stone-100"
            onClick={onLogout}
          >
            Logout
          </button>
        </div>
      )}
      {isAccountsOpen && (
        <div className="absolute left-48 top-0 w-48 bg-white border border-stone-300 shadow-lg z-20 max-h-60 overflow-y-auto">
          {accounts.map((account) => (
            <button
              key={account}
              className="block w-full text-left px-4 py-2 text-sm text-stone-700 hover:bg-stone-100"
              onClick={() => {
                onSelectAccount(account);
                setIsAccountsOpen(false);
                setIsOpen(false);
              }}
            >
              {account}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default UserDropdown;

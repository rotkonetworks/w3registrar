import React, { useState, useEffect } from 'react';

const NetworkDropdown = ({ network, setNetwork }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [customWs, setCustomWs] = useState('');

  const networks = ['Kusama', 'Polkadot', 'Paseo', 'Custom'];

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="bg-stone-200 text-stone-800 px-3 py-1 text-sm font-medium border border-stone-400 w-full text-left"
      >
        {network} ▼
      </button>
      {isOpen && (
        <div className="absolute right-0 mt-1 w-48 bg-white border border-stone-300 shadow-lg z-10">
          {networks.map((net) => (
            <button
              key={net}
              className="block w-full text-left px-4 py-2 text-sm text-stone-700 hover:bg-stone-100"
              onClick={() => {
                setNetwork(net);
                setIsOpen(false);
              }}
            >
              {net}
            </button>
          ))}
          {network === 'Custom' && (
            <input
              type="text"
              value={customWs}
              onChange={(e) => setCustomWs(e.target.value)}
              placeholder="Enter WebSocket URL"
              className="w-full px-4 py-2 text-sm border-t border-stone-300"
            />
          )}
        </div>
      )}
    </div>
  );
};

export default NetworkDropdown;

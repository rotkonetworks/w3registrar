import React, { useState, useEffect } from 'react';

const ProgressBar = ({ progress }) => (
  <div className="mb-6">
    <div className="relative pt-1">
      <div className="overflow-hidden h-2 mb-4 text-xs flex bg-stone-300">
        <div
          style={{ width: `${progress}%` }}
          className="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-stone-600 transition-all duration-500"
        />
      </div>
    </div>
  </div>
);

export default ProgressBar;

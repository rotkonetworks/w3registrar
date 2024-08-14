import React, { useState, useEffect } from 'react';

const CountdownTimer = () => {
  const [time, setTime] = useState(5 * 3600 + 45 * 60 + 15); // use valtio

  useEffect(() => {
    const timer = setInterval(() => {
      setTime((prevTime) => (prevTime > 0 ? prevTime - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2, '0')}h ${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`;
  };

  return (
    <div className="bg-red-900 text-red-100 px-3 py-1 text-sm font-medium">
      {formatTime(time)}
    </div>
  );
};

export default CountdownTimer;

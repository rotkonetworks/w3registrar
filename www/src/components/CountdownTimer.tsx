import { createSignal, createEffect } from "solid-js";

const CountdownTimer = () => {
  const [time, setTime] = createSignal<number>(5 * 3600 + 45 * 60 + 15);

  createEffect(() => {
    if (time() > 0) {
      const timer = setInterval(() => setTime(t => t - 1), 1000);
      return () => clearInterval(timer);
    } else {
      console.warn("Time's up!");
    }
  });

  const formatTime = (s: number): string => {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
  };

  return (
    <div class="w-[200px] rounded-full bg-gray-100 border-2 border-gray-300 px-[2rem] py-[1rem] text-center">
      {formatTime(time())}
    </div>
  );
};

export default CountdownTimer;

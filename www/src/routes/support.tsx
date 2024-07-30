import { A } from "@solidjs/router";
        // TODO: iframe some loginable matrix/element support channel here

export default function Support() {
  return (
    <main class="text-center mx-auto text-gray-700 p-4">
      <h1 class="max-6-xs text-6xl text-sky-700 font-thin uppercase my-16">
        Support Page
      </h1>
      <div class="mt-5">
        <p class="text-lg text-black">For updates and more information, follow us on our 
          <a href="https://matrix.to/#/#w3reg:matrix.org" target="_blank" class="text-blue-700 underline">Matrix channel</a>.
        </p>
      </div>
    </main>
  );
}

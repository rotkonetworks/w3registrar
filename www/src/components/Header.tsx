import { createSignal, createEffect } from "solid-js";
import {
  getInjectedExtensions,
  connectInjectedExtension,
  InjectedPolkadotAccount,
} from "polkadot-api/pjs-signer";

const Header = () => {
  const [isLoggedIn, setIsLoggedIn] = createSignal(false);
  const [accounts, setAccounts] = createSignal<InjectedPolkadotAccount[]>([]);
  const [selectedAccount, setSelectedAccount] = createSignal<InjectedPolkadotAccount | null>(null);

  createEffect(() => {
    const checkExtension = async () => {
      while (!getInjectedExtensions()?.includes("polkadot-js"))
        await new Promise((res) => setTimeout(res, 50));

      const pjs = await connectInjectedExtension("polkadot-js");
      const userAccounts = await pjs.getAccounts();
      setAccounts(userAccounts);

      if (userAccounts.length > 0) {
        setSelectedAccount(userAccounts[0]);
        setIsLoggedIn(true);
      }
    };

    checkExtension();
  });

  const handleAccountChange = (event: Event) => {
    const target = event.target as HTMLSelectElement;
    const index = parseInt(target.value, 10);
    setSelectedAccount(accounts()[index]);
  };

  const shortenAddress = (address: string) => `${address.slice(0, 6)}...${address.slice(-4)}`;

  return (
    <header class="flex items-center justify-between mb-6">
      <div class="text-lg font-bold">OxAccountId</div>
      <div class="text-red-600">TTL: 5h 45m 15s</div>
      <div>
        {isLoggedIn() ? (
          <div class="flex items-center">
            <select
              class="mr-4 px-2 py-1 border rounded"
              onChange={handleAccountChange}
              value={accounts().indexOf(selectedAccount()!)}
            >
              {accounts().map((account, index) => (
                <option value={index} key={account.address}>
                  {shortenAddress(account.address)}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <button class="px-4 py-2 bg-blue-500 text-white rounded" onClick={() => setIsLoggedIn(true)}>
            Sign In
          </button>
        )}
      </div>
    </header>
  );
};

export default Header;

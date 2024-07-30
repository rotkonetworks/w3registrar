import { Component, For } from 'solid-js';
import { createStore } from 'solid-js/store';
import { IdentityField } from '../types';
import Input from './Input';

interface IdentityFormProps {
  fields: IdentityField[];
}

const IdentityForm: Component<IdentityFormProps> = (props) => {
  const [formData, setFormData] = createStore(
    props.fields.reduce((acc, field) => ({ ...acc, [field.id]: '' }), {})
  );

  const handleInputChange = (id: string, value: string) => {
    setFormData({ [id]: value });
  };

  const handleSubmit = (e: Event) => {
    e.preventDefault();
    console.log('Form submitted with data:', formData);
  };

  return (
    <form onSubmit={handleSubmit} class="space-y-4">
      <div class="text-center">
        <h2 class="text-2xl font-bold">Identity</h2>
      </div>
      <div class="space-y-2">
        <For each={props.fields}>
          {(field) => (
            <Input
              id={field.id}
              placeholder={field.placeholder}
              type={field.type}
              value={formData[field.id]}
              onInput={(e) => handleInputChange(field.id, (e.target as HTMLInputElement).value)}
            />
          )}
        </For>
      </div>
      <button
        type="submit"
        class="inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2 w-full mt-4"
      >
        Submit
      </button>
    </form>
  );
};

export default IdentityForm;

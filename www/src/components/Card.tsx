import { Component, JSX } from 'solid-js';

interface CardProps {
  children: JSX.Element;
}

interface CardHeaderProps {
  title: string;
  subtitle: string;
}

const Card: Component<CardProps> & {
  Header: Component<CardHeaderProps>;
  Content: Component<CardProps>;
  Footer: Component<CardProps>;
} = (props) => (
  <div class="rounded-lg border bg-card text-card-foreground shadow-sm w-full max-w-3xl" data-v0-t="card">
    {props.children}
  </div>
);

Card.Header = (props) => (
  <div class="flex-col space-y-1.5 p-6 flex justify-between items-center">
    <span class="text-xl font-bold">{props.title}</span>
    <div class="inline-flex w-fit items-center whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-primary text-primary-foreground hover:bg-primary/80" data-v0-t="badge">
      {props.subtitle}
    </div>
  </div>
);

Card.Content = (props) => <div class="p-6">{props.children}</div>;
Card.Footer = (props) => <div class="flex items-center p-6 text-sm text-gray-500">{props.children}</div>;

export default Card;

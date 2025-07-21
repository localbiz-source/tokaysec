import type { Preview } from '@storybook/sveltekit'

const preview: Preview = {
  parameters: {
    backgrounds: {
      options: {
        dark: { name: "Dark", value: "oklch(14.5% 0 0)" }
      }
    },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  initialGlobals: {
    backgrounds: { value: 'dark' }
  },
};

export default preview;
<script module>
  import { defineMeta } from "@storybook/addon-svelte-csf";
  import Button from "./Button.svelte";
  import { fn } from "storybook/test";
  import ArrowIcon from "./ArrowIcon.svelte";

  // More on how to set up stories at: https://storybook.js.org/docs/writing-stories
  const { Story } = defineMeta({
    title: "Example/Button",
    component: Button,
    tags: ["autodocs"],
    argTypes: {
      // backgroundColor: { control: 'color' },
      // size: {
      //   control: { type: 'select' },
      //   options: ['small', 'medium', 'large'],
      // },
      // block: { type: "boolean" }
    },
    args: {
      onclick: fn(),
    },
  });
</script>

<!-- More on writing stories with args: https://storybook.js.org/docs/writing-stories/args -->
<Story name="Primary" args={{ style: "primary", label: "Button" }} />

<Story name="Ghost" args={{ style: "ghost", label: "Button" }} />

<Story
  name="PrimaryWithIcon"
  args={{ style: "primary", label: "Button", icon: ArrowIcon }}
/>

<Story
  name="GhostWithIcon"
  args={{ style: "ghost", label: "Button", icon: ArrowIcon }}
/>
<!-- <Story name="Secondary" args={{ label: 'Button' }} />

<Story name="Large" args={{ size: 'large', label: 'Button' }} />

<Story name="Small" args={{ size: 'small', label: 'Button' }} /> -->

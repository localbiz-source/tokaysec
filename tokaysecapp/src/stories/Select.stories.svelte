<script module>
  import { defineMeta } from "@storybook/addon-svelte-csf";
  import Select from "./Select.svelte";
  import { fn } from "storybook/test";

  // More on how to set up stories at: https://storybook.js.org/docs/writing-stories
  const { Story } = defineMeta({
    title: "Example/Select",
    component: Select,
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
<Story name="Normal" args={{ label: "Secret Name", options: ["Key-Value"] }} />

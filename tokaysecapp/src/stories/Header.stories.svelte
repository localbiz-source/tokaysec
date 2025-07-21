<script module>
  import { defineMeta } from "@storybook/addon-svelte-csf";
  import Header from "./Header.svelte";
  import { fn } from "storybook/test";

  // More on how to set up stories at: https://storybook.js.org/docs/writing-stories
  const { Story } = defineMeta({
    title: "Example/Header",
    component: Header,
    tags: ["autodocs"],
    argTypes: {},
    args: {
      onclick: fn(),
    },
  });
</script>

<!-- More on writing stories with args: https://storybook.js.org/docs/writing-stories/args -->
<Story name="Top" args={{ level: "top", header:" What" }} />
<Story name="Middle" args={{ level: "middle", header:" What" }} />
<Story name="Low" args={{ level: "low", header:" What" }} />

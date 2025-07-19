<script module>
  import { defineMeta } from "@storybook/addon-svelte-csf";
  import ButtonGroup from "./ButtonGroup.svelte";
  import { fn } from "storybook/test";
  import ArrowIcon from "./ArrowIcon.svelte";

  // More on how to set up stories at: https://storybook.js.org/docs/writing-stories
  const { Story } = defineMeta({
    title: "Example/ButtonGroup",
    component: ButtonGroup,
    tags: ["autodocs"],
    argTypes: {},
    args: {},
  });
</script>

<Story name="ButtonGroup" args={{
    members: [
        { style: "primary", label: "Create", icon: ArrowIcon },
        { style: "ghost", label: "Cancel" }
    ]
}} />

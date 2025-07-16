<script lang="ts">
  import "../app.css";
  import classNames from "classnames";
  import type { Component } from "svelte";

  export interface Props {
    /** Button Style */
    style: "primary" | "ghost" | undefined;
    /** Button is block? */
    block?: boolean;
    /** Part of button group */
    partOfButtonGroup?: boolean;
    /** Button contents */
    label: string;
    /** Icon? */
    icon?: Component;
    /** The onclick event handler */
    onclick?: () => void;
  }

  const {
    style = "primary",
    label,
    icon,
    block = false,
    partOfButtonGroup = false,
    ...props
  }: Props = $props();

  const IconComp = $derived(icon ? icon : null);
  let buttonStyles = $derived(
    classNames(
      "flex w-full cursor-pointer flex-col items-start justify-start border-2 p-2 outline-2 transition-all duration-150",
      {
        "text-white border-amber-500 bg-amber-500 outline-amber-500 transition-all duration-150 hover:border-amber-400 hover:bg-amber-400 hover:outline-amber-400 focus:border-amber-500 focus:bg-amber-500 focus:outline-amber-900 active:border-amber-500 active:bg-amber-500 active:outline-amber-900":
          style == "primary",
        "text-white border-neutral-500 bg-neutral-500 outline-neutral-500 transition-all duration-150 hover:border-neutral-400 hover:bg-neutral-400 hover:outline-neutral-400 focus:border-neutral-500 focus:bg-neutral-500 focus:outline-neutral-900 active:border-neutral-500 active:bg-neutral-500 active:outline-neutral-900":
          style == "ghost",
        "max-w-[14rem]": !block,
        "h-[4rem]": partOfButtonGroup,
      },
    ),
  );
</script>

<button type="button" class={buttonStyles} {...props}>
  <div class="flex w-full flex-row justify-between items-center text-white">
    <span class="font-['Myriad-Pro']">{label}</span>
    {#if IconComp}
      <IconComp />
    {/if}
  </div>
</button>

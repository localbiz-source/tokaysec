<script lang="ts">
  import "../app.css";
  import classNames from "classnames";
  import type { Component } from "svelte";

  export interface Props {
    /** Button Style */
    style: "primary" | "ghost";
    /** Button is block? */
    block?: boolean;
    /** Part of button group */
    partOfButtonGroup?: boolean;
    /** Button contents */
    label?: string;
    /** Icon? */
    icon?: Component;
    /** Is the button loading */
    loading?: boolean;
    /** The onclick event handler */
    onclick?: () => void;
  }

  const {
    style,
    label,
    icon,
    loading,
    block = false,
    partOfButtonGroup = false,
    ...props
  }: Props = $props();

  const IconComp = $derived(icon ? icon : null);
  let buttonStyles = $derived(
    classNames(
      "flex w-full cursor-pointer flex-col items-start justify-start border-2 p-2 outline-2 transition-all duration-150",
      {
        "disabled:bg-amber-700 disabled:cursor-not-allowed disabled:outline-amber-700 disabled:border-amber-700 disabled:text-white/70 text-white border-amber-500 bg-amber-500 outline-amber-500 transition-all duration-150 hover:border-amber-400 hover:bg-amber-400 hover:outline-amber-400 focus:border-white focus:bg-amber-500 focus:outline-white active:border-amber-500 active:bg-amber-500 active:outline-amber-900":
          style == "primary",
        "disabled:bg-gray-600 disabled:cursor-not-allowed disabled:outline-gray-600 disabled:border-gray-600 disabled:text-white/70 text-white border-neutral-500 bg-neutral-500 outline-neutral-500 transition-all duration-150 hover:border-neutral-400 hover:bg-neutral-400 hover:outline-neutral-400 focus:border-white focus:bg-neutral-500 focus:outline-white active:border-neutral-500 active:bg-neutral-500 active:outline-neutral-900":
          style == "ghost",
        "max-w-[14rem]": !block,
        "max-w-max": !label,
        "h-[4rem]": partOfButtonGroup,
      },
    ),
  );
</script>

<button disabled={loading} type="button" class={buttonStyles} {...props}>
  <div class="flex w-full flex-row justify-between items-center">
    {#if label}
      <span class="font-['Myriad-Pro']">{label}</span>
    {/if}
    {#if loading}
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        class={classNames("animate-spin", {
          "stroke-amber-100": style == "primary",
          "stroke-gray-200": style == "ghost",
        })}
        ><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path
          d="M12 6l0 -3"
        /><path d="M16.25 7.75l2.15 -2.15" /><path d="M18 12l3 0" /><path
          d="M16.25 16.25l2.15 2.15"
        /><path d="M12 18l0 3" /><path d="M7.75 16.25l-2.15 2.15" /><path
          d="M6 12l-3 0"
        /><path d="M7.75 7.75l-2.15 -2.15" /></svg
      >
    {:else if IconComp}
      <IconComp />
    {/if}
  </div>
</button>

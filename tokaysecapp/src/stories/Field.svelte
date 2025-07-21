<script lang="ts">
    import "../app.css";
    import classNames from "classnames";
    import type { Component } from "svelte";

    export interface Props {
        label: string;
        partOfModel?: boolean;
    }

    const { partOfModel, label, ...props }: Props = $props();

    let fieldStyles = $derived(
        classNames(
            "w-full text-white border-1 border-l-2 border-l-neutral-500 border-neutral-700 bg-neutral-700 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-700 transition-all duration-150 focus:border-l-1 active:border-l-1 hover:border-l-1 hover:border-neutral-300 focus:border-neutral-400 focus:bg-neutral-700 focus:outline-white",
        ),
    );
    let surroundingBoxStyles = $derived(
        classNames("w-full", {
            "px-0.5": partOfModel,
        }),
    );
</script>

<div class="text-white flex w-full flex-col gap-2">
    <span class="text-md font-['Myriad-Pro']">{label}</span>
    <div class={surroundingBoxStyles}>
        <input class={fieldStyles} {...props} />
    </div>
</div>

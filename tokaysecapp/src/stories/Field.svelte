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
            "w-full border-1 border-neutral-200 bg-neutral-200 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-200 transition-all duration-150 hover:outline-neutral-500 focus:border-black focus:bg-white focus:outline-black",
        ),
    );
    let surroundingBoxStyles = $derived(
        classNames("w-full", {
            "px-0.5": partOfModel,
        }),
    );
</script>

<div class="flex w-full flex-col gap-2">
    <span class="text-md font-['Myriad-Pro']">{label}</span>
    <div class={surroundingBoxStyles}>
        <input class={fieldStyles} {...props} />
    </div>
</div>

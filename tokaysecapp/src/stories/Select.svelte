<script lang="ts">
    import "../app.css";
    import classNames from "classnames";

    export interface Props {
        label: string;
        options: string[];
        partOfModel?: boolean;
    }

    const { partOfModel, label, options, ...props }: Props = $props();

    let fieldStyles = $derived(
        classNames(
            "w-full border-1 border-neutral-200 bg-neutral-200 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-200 transition-all duration-150 hover:outline-neutral-500 focus:border-black focus:bg-white focus:outline-black",
        ),
    );
    let surroundingBoxStyles = $derived(
        classNames("flex w-full flex-row relative", {
            "px-0.5": partOfModel,
        }),
    );
</script>

<div class="text-white flex w-full flex-col gap-2">
    <span class="text-md font-['Myriad-Pro']">{label}</span>
    <div class={surroundingBoxStyles}>
        <select
            class="cursor-pointer appearance-none w-full text-white border-1 border-l-2 border-l-neutral-500 border-neutral-700 bg-neutral-700 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-700 transition-all duration-150 focus:border-l-1 active:border-l-1 hover:border-l-1 hover:border-neutral-300 focus:border-neutral-400 focus:bg-neutral-700 focus:outline-white"
        >
            <option>--</option>
            {#each options as option}
                <option>{option}</option>
            {/each}
        </select>
        <div
            class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-500"
        >
            <!-- Down arrow icon (Heroicons or SVG) -->
            <svg
                class="h-4 w-4"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M19 9l-7 7-7-7"
                />
            </svg>
        </div>
    </div>
</div>

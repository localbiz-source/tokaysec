<script>
    import Header from "../stories/Header.svelte";
    import AddSecretIcon from "../stories/AddSecretIcon.svelte";
    import CogIcon from "../stories/CogIcon.svelte";
    import Button from "../stories/Button.svelte";
    import "../app.css";
    import ArrowIcon from "../stories/ArrowIcon.svelte";
    import ButtonGroup from "../stories/ButtonGroup.svelte";
    import AddPersonIcon from "../stories/AddPersonIcon.svelte";
    import secrets from "./stores.ts";
    import { onMount } from "svelte";
    import chroma from "chroma-js";
    import HistoryIcon from "../stories/HistoryIcon.svelte";
    import LockIcon from "../stories/LockIcon.svelte";
    import CopyIcon from "../stories/CopyIcon.svelte";

    function getReadableTextColor(/** @type {string} */ bgColor) {
        return chroma.contrast(bgColor, "white") >
            chroma.contrast(bgColor, "black")
            ? "white"
            : "black";
    }

    onMount(() => {
        fetch(
            "http://localhost:2323/v1/projects/7352141003882500096/secrets",
        ).then((res) =>
            res.json().then((json) => {
                // todo: types.
                $secrets = json.map((/** @type {any} */ v) => {
                    return {
                        color: chroma.random(),
                        ...v,
                    };
                });
            }),
        );
    });
</script>

<div class="w-screen h-screen dark:bg-[oklch(14.5%_0_0)]">
    <div
        class="bg-neutral-800 w-full rounded-tl-3xl border-l border-t border-white/10"
    >
        <div class="flex flex-col rounded-xl bg-neutral-800 rounded-tl-3xl">
            <div
                class="w-full pl-3 pt-3 bg-white/10 backdrop-blur shadow-md rounded-tl-3xl border-l border-t border-white/10"
            >
                <header
                    class="w-full bg-linear-65 from-purple-500 to-pink-500 h-81 flex flex-row items-end justify-between px-5 py-2 rounded-tl-3xl border-l border-t border-white/20"
                >
                    <ul class="flex flex-col">
                        <Header level="middle" header="project" />
                        <Header level="display" header="Default" />
                    </ul>
                    <div
                        class="flex flex-col px-3 items-start justify-end bg-neutral-500 p-1 border border-white shadow-lg"
                    >
                        <span class="font-['Myriad-Pro'] text-white text-xs"
                            >Project KEK Rotation In</span
                        >
                        <Header level="super-low" header={"23 days"} />
                    </div>
                </header>
            </div>
        </div>
        <div
            class="flex flex-col gap-3 p-0.5 bg-white/10 backdrop-blur shadow-md border-b border-r border-white/10"
        >
            <ButtonGroup
                members={[
                    {
                        style: "primary",
                        label: "Add Secret",
                        icon: AddSecretIcon,
                        //onclick: () => ($secrets = ["meow", ...$secrets]),
                    },
                    {
                        style: "ghost",
                        label: "Settings",
                        icon: CogIcon,
                        //onclick: () => ($secrets = ["meow", ...$secrets]),
                    },
                ]}
            />
        </div>
    </div>
    <div class="flex flex-col pt-0.5 pr-0.5 w-screen">
        {#if $secrets}
            {#each $secrets as secret, index}
                <div
                    class="flex flex-row gap-5 items-center justify-between bg-neutral-800 border-b border-white/10"
                >
                    <div class="flex flex-row items-center gap-5">
                        <span
                            class="flex bg-neutral-800 flex-row items-center justify-center px-3 py-2 rounded-br-lg border-b border-r border-white/10"
                            style={`background:${secret["color"]};`}
                        >
                            <Header
                                level="low"
                                textColor={getReadableTextColor(
                                    secret["color"],
                                )}
                                header={(index + 1).toString()}
                            />
                        </span>
                        <Header level="low" header={secret["name"]} />
                        <div class="flex flex-row">
                            <div
                                class="flex flex-col px-3 items-start justify-end bg-neutral-500 p-1 border border-white/10"
                            >
                                <span
                                    class="font-['Myriad-Pro'] text-white text-xs"
                                    >Stored In</span
                                >
                                <Header
                                    level="super-low"
                                    header={secret["store_used"]}
                                />
                            </div>
                            <div
                                class="flex flex-col px-3 items-start justify-end bg-neutral-500 p-1 border border-white/10"
                            >
                                <span
                                    class="font-['Myriad-Pro'] text-white text-xs"
                                    >DEK Rotation In</span
                                >
                                <Header
                                    level="super-low"
                                    header={"1 day 2 hours 14 minutes"}
                                />
                            </div>
                        </div>
                    </div>
                    <ButtonGroup
                        members={[
                            {
                                style: "ghost",
                                icon: LockIcon,
                                partOfButtonGroup: false,
                            },
                            {
                                style: "ghost",
                                icon: HistoryIcon,
                                partOfButtonGroup: false,
                            },
                            {
                                style: "ghost",
                                icon: CogIcon,
                                partOfButtonGroup: false,
                            },
                        ]}
                    />
                </div>
            {/each}
        {/if}
    </div>
</div>

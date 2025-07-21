<script lang="ts">
    import "../app.css";
    import classNames from "classnames";
    import type { Component } from "svelte";

    export interface Props {
        /** Header Level */
        level?: "top" | "middle" | "low" | "display" | "super-low";
        header: string;
        textColor?: string;
        onclick?: () => void;
    }

    const { level = "low", header, textColor, ...props }: Props = $props();
</script>

<span
    style={`color:${textColor ? `${textColor} !important` : ""}`}
    class={classNames("font-['Myriad-Pro'] text-white", {
        "text-5xl font-['ethnocentric']! font-light": level == "display",
        "text-2xl": level == "top",
        "text-xl": level == "middle",
        "text-lg": level == "low",
        "text-sm": level == "super-low"
    })}>{header}</span
>

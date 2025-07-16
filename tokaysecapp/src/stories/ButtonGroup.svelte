<script lang="ts">
    import "../app.css";
    import classNames from "classnames";
    import type { Component } from "svelte";
    import type { Props as ButtonProps } from "./Button.svelte";
    import Button from "./Button.svelte";

    interface Props {
        members: ButtonProps[];
    }

    const { members = [], ...props }: Props = $props();
</script>

<div class="flex flex-row gap-1">
    {#each members as member}
        <Button partOfButtonGroup={true} {...member}/>
    {/each}
</div>

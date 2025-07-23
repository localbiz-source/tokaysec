<script lang="ts">
    import type { Snippet } from "svelte";

    const props: {
        namespaceId?: string;
        projectId?: string;
        children?: Snippet;
    } = $props();
</script>

<div class="flex flex-col">
    {@render props.children?.()}
</div>

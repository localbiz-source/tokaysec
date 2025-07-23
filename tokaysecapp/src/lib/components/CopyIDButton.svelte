<script lang="ts">
    export let id: string;
    import { Clipboard } from "@lucide/svelte";
    import { Button } from "$lib/components/ui/button";
    import { toast } from "svelte-sonner";
    async function copy() {
        await navigator.clipboard.writeText(id);
        toast.success("Secret ID copied to your clipboard!");
    }
</script>

<Button onclick={copy} variant="outline" size="sm">
    <Clipboard />
    Copy ID
</Button>

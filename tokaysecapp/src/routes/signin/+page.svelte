<script lang="ts" generics="TData, TValue">
    import "../../app.css";
    import { Button, buttonVariants } from "$lib/components/ui/button/index.ts";
    import * as Sheet from "$lib/components/ui/sheet/index.js";
    import * as Select from "$lib/components/ui/select/index.js";
    import * as Alert from "$lib/components/ui/alert/index.js";
    import { onMount, type Snippet } from "svelte";
    import type { PageData } from "./$types.ts";
    import { AlertCircleIcon } from "@lucide/svelte";
    import { page } from "$app/state";
    import { goto } from "$app/navigation";

    const props: {
        data: PageData;
        children?: Snippet;
    } = $props();
    let loginOptions: {
        oidc?: [{ name: string; url: string }];
    } = $state({});
    $effect(() => {
        fetch(`https://staging.jiternal.com/api/v1/auth/options`).then((res) =>
            res.json().then((json) => {
                // todo: types.
                loginOptions = json;
            }),
        );
    });
</script>

<div class="w-full h-full p-10 bg-background flex flex-col gap-3 relative">
    {#if loginOptions["oidc"]}
        <div class="flex flex-col gap-3 max-w-max">
            {#each loginOptions["oidc"] as provider}
                <Button
                    onclick={(_) => {
                        window.location.href = provider.url;
                    }}
                    variant="outline"
                    size="sm">Sign in with {provider.name}</Button
                >
            {/each}
        </div>
    {/if}
</div>

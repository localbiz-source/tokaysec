<script lang="ts">
    import * as Sidebar from "$lib/components/ui/sidebar/index.js";
    import { Toaster } from "$lib/components/ui/sonner/index.js";
    import AppSidebar from "$lib/components/app-sidebar.svelte";
    let { children } = $props();
</script>

<Sidebar.Provider>
    <AppSidebar />
    <main class="w-full h-full">
        <Toaster />
        <Sidebar.Trigger />
        {@render children?.()}
    </main>
</Sidebar.Provider>

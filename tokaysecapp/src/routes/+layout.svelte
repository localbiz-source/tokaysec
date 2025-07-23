<script lang="ts">
    import * as Sidebar from "$lib/components/ui/sidebar/index.js";
    import { Toaster } from "$lib/components/ui/sonner/index.js";
    import { ModeWatcher } from "mode-watcher";

    import AppSidebar from "$lib/components/app-sidebar.svelte";
    import "../app.css";
    let { children } = $props();
</script>

<Sidebar.Provider>
    <main class="w-full h-full">
        <Toaster />
        <ModeWatcher />

        {@render children?.()}
    </main>
</Sidebar.Provider>

<script lang="ts">
    const props = $props();
    import * as Sidebar from "$lib/components/ui/sidebar/index.js";
    import * as DropdownMenu from "$lib/components/ui/dropdown-menu/index.js";
    import { ChevronDown, CogIcon, SquareAsterisk } from "@lucide/svelte";
    import global_state from "../../routes/namespaceAndProject";
    import { goto } from "$app/navigation";
    import { page } from "$app/state";
    const namespaces = [
        {
            id: "7352140924266221570",
            name: "default_namespace",
        },
    ];
    const namespaceTriggerContent = $derived(
        namespaces.find((f) => f.id == props.namespaceId)?.name ??
            "Select a namespace",
    );
    const projects = [
        {
            id: "7352141083272286208",
            name: "top_secret_project",
        },
        {
            id: "7352141003882500096",
            name: "default_projcet",
        },
    ];
    const projectTriggerContent = $derived(
        projects.find((f) => f.id == props.projectId)?.name ??
            "Select a project",
    );
</script>

<Sidebar.Root>
    <Sidebar.Header>
        <Sidebar.Menu>
            <Sidebar.MenuItem>
                <DropdownMenu.Root>
                    <DropdownMenu.Trigger>
                        {#snippet child({ props })}
                            <Sidebar.MenuButton {...props}>
                                {namespaceTriggerContent}
                                <ChevronDown class="ml-auto" />
                            </Sidebar.MenuButton>
                        {/snippet}
                    </DropdownMenu.Trigger>
                    <DropdownMenu.Content
                        class="w-(--bits-dropdown-menu-anchor-width)"
                    >
                        {#each namespaces as namespace}
                            <DropdownMenu.Item
                                onclick={(_) =>goto(`/namespace/${namespace.id}`)}
                            >
                                <span>{namespace.name}</span>
                            </DropdownMenu.Item>
                        {/each}
                    </DropdownMenu.Content>
                </DropdownMenu.Root>
            </Sidebar.MenuItem>
        </Sidebar.Menu>
    </Sidebar.Header>
    <Sidebar.Content>
        {#if props.namespaceId}
            <Sidebar.Group>
                <Sidebar.GroupLabel
                    ><DropdownMenu.Root>
                        <DropdownMenu.Trigger>
                            {#snippet child({ props })}
                                <Sidebar.MenuButton {...props}>
                                    {projectTriggerContent}
                                    <ChevronDown class="ml-auto" />
                                </Sidebar.MenuButton>
                            {/snippet}
                        </DropdownMenu.Trigger>
                        <DropdownMenu.Content
                            class="w-(--bits-dropdown-menu-anchor-width)"
                        >
                            {#each projects as project}
                                <DropdownMenu.Item
                                    onclick={(_) => {goto(`/namespace/${page.params.namespaceId}/project/${project.id}`)}}
                                >
                                    <span>{project.name}</span>
                                </DropdownMenu.Item>
                            {/each}
                        </DropdownMenu.Content>
                    </DropdownMenu.Root></Sidebar.GroupLabel
                >
                <Sidebar.GroupContent>
                    {#if props.projectId}
                        <Sidebar.MenuSub>
                            <Sidebar.MenuSubItem>
                                <Sidebar.MenuButton>
                                    {#snippet child({ props })}
                                        <a href={`/namespace/${page.params.namespaceId}/project/${page.params.projectId}/secrets`} {...props}>
                                            <SquareAsterisk />
                                            <span>Secrets</span>
                                        </a>
                                    {/snippet}
                                </Sidebar.MenuButton>
                            </Sidebar.MenuSubItem>
                            <Sidebar.MenuSubItem>
                                <Sidebar.MenuButton>
                                    {#snippet child({ props })}
                                        <a href={`/namespace/${page.params.namespaceId}/project/${page.params.projectId}/settings`} {...props}>
                                            <CogIcon />
                                            <span>Settings</span>
                                        </a>
                                    {/snippet}
                                </Sidebar.MenuButton>
                            </Sidebar.MenuSubItem>
                        </Sidebar.MenuSub>
                    {/if}
                </Sidebar.GroupContent>
            </Sidebar.Group>
        {/if}
    </Sidebar.Content>
    <Sidebar.Footer />
</Sidebar.Root>

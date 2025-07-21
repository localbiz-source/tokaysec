<script lang="ts">
    import * as Sidebar from "$lib/components/ui/sidebar/index.js";
    import * as DropdownMenu from "$lib/components/ui/dropdown-menu/index.js";
    import { ChevronDown, SquareAsterisk } from "@lucide/svelte";
</script>

<Sidebar.Root>
    <Sidebar.Header>
        <Sidebar.Menu>
            <Sidebar.MenuItem>
                <DropdownMenu.Root>
                    <DropdownMenu.Trigger>
                        {#snippet child({ props })}
                            <Sidebar.MenuButton {...props}>
                                Select Workspace
                                <ChevronDown class="ml-auto" />
                            </Sidebar.MenuButton>
                        {/snippet}
                    </DropdownMenu.Trigger>
                    <DropdownMenu.Content
                        class="w-(--bits-dropdown-menu-anchor-width)"
                    >
                        <DropdownMenu.Item>
                            <span>Default</span>
                        </DropdownMenu.Item>
                    </DropdownMenu.Content>
                </DropdownMenu.Root>
            </Sidebar.MenuItem>
        </Sidebar.Menu>
    </Sidebar.Header>
    <Sidebar.Content>
        <Sidebar.Group>
            <Sidebar.GroupLabel>Project</Sidebar.GroupLabel>
            <Sidebar.GroupContent>
                <Sidebar.MenuSub>
                    <Sidebar.MenuSubItem>
                        <DropdownMenu.Root>
                            <DropdownMenu.Trigger>
                                {#snippet child({ props })}
                                    <Sidebar.MenuButton {...props}>
                                        Select Project
                                        <ChevronDown class="ml-auto" />
                                    </Sidebar.MenuButton>
                                {/snippet}
                            </DropdownMenu.Trigger>
                            <DropdownMenu.Content
                                class="w-(--bits-dropdown-menu-anchor-width)"
                            >
                                <DropdownMenu.Item>
                                    <span>Default</span>
                                </DropdownMenu.Item>
                            </DropdownMenu.Content>
                        </DropdownMenu.Root>
                    </Sidebar.MenuSubItem>
                </Sidebar.MenuSub>
                <Sidebar.MenuSub>
                    <Sidebar.MenuSubItem>
                        <Sidebar.MenuButton>
                            {#snippet child({ props })}
                                <a href={"/"} {...props}>
                                    <SquareAsterisk />
                                    <span>Secrets</span>
                                </a>
                            {/snippet}
                        </Sidebar.MenuButton>
                    </Sidebar.MenuSubItem>
                </Sidebar.MenuSub></Sidebar.GroupContent
            >
        </Sidebar.Group>
    </Sidebar.Content>
    <Sidebar.Footer />
</Sidebar.Root>

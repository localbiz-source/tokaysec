<script lang="ts">
  import AppSidebar from "$lib/components/app-sidebar.svelte";
  import * as Sidebar from "$lib/components/ui/sidebar/index.js";
  import { Separator } from "$lib/components/ui/separator/index.js";
  import * as Breadcrumb from "$lib/components/ui/breadcrumb/index.js";
  import * as DropdownMenu from "$lib/components/ui/dropdown-menu/index.js";
  import { ChevronDown, CogIcon, SquareAsterisk } from "@lucide/svelte";
  import { goto } from "$app/navigation";
  import type { Snippet } from "svelte";
  import { page } from "$app/state";
  const props: {
    children?: Snippet;
  } = $props();

  const namespaces = [
    {
      id: "7352140924266221570",
      name: "default_namespace",
    },
  ];
  const namespaceTriggerContent = $derived(
    namespaces.find((f) => f.id == page.params.namespaceId)?.name ??
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
    projects.find((f) => f.id == page.params.projectId)?.name ??
      "Select a project",
  );
</script>

<Sidebar.Provider>
  <AppSidebar
    namespaceId={page.params.namespaceId}
    projectId={page.params.projectId}
  />
  <main class="w-full h-full">
    <Sidebar.Trigger />
    <div class="flex flex-col">
      <div class="px-10">
        <Breadcrumb.Root>
          <Breadcrumb.List>
            <Breadcrumb.Item>
              <Breadcrumb.Link href="/">Home</Breadcrumb.Link>
            </Breadcrumb.Item>
            <Breadcrumb.Separator />
            <Breadcrumb.Item>
              <Breadcrumb.Link href={`/namespace`}>Namespace</Breadcrumb.Link>
            </Breadcrumb.Item>
            <Breadcrumb.Separator />
            <Breadcrumb.Item>
              <DropdownMenu.Root>
                <DropdownMenu.Trigger class="flex items-center gap-1">
                  {namespaceTriggerContent}
                  <ChevronDown class="ml-auto" />
                </DropdownMenu.Trigger>
                <DropdownMenu.Content
                  class="w-(--bits-dropdown-menu-anchor-width)"
                >
                  {#each namespaces as namespace}
                    <DropdownMenu.Item
                      onclick={(_) => goto(`/namespace/${namespace.id}`)}
                    >
                      <span>{namespace.name}</span>
                    </DropdownMenu.Item>
                  {/each}
                </DropdownMenu.Content>
              </DropdownMenu.Root>
            </Breadcrumb.Item>
            <Breadcrumb.Separator />
            <Breadcrumb.Item>
              <Breadcrumb.Link
                href={`/namespace/${page.params.namespaceId}/project`}
                >Projects</Breadcrumb.Link
              >
            </Breadcrumb.Item>
            <Breadcrumb.Separator />
            <Breadcrumb.Item>
              <DropdownMenu.Root>
                <DropdownMenu.Trigger class="flex items-center gap-1">
                  {projectTriggerContent}
                  <ChevronDown class="ml-auto" />
                </DropdownMenu.Trigger>
                <DropdownMenu.Content
                  class="w-(--bits-dropdown-menu-anchor-width)"
                >
                  {#each projects as project}
                    <DropdownMenu.Item
                      onclick={(_) => goto(`/namespace/${page.params.namespaceId}/project/${project.id}`)}
                    >
                      <span>{project.name}</span>
                    </DropdownMenu.Item>
                  {/each}
                </DropdownMenu.Content>
              </DropdownMenu.Root>
            </Breadcrumb.Item>
          </Breadcrumb.List>
        </Breadcrumb.Root>
        <Separator class="my-4" />
      </div>
      {@render props.children?.()}
    </div>
  </main>
</Sidebar.Provider>

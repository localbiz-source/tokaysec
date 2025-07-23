<script lang="ts" generics="TData, TValue">
    import "../../../../../../app.css";
    import { Button, buttonVariants } from "$lib/components/ui/button/index.ts";
    import * as Sheet from "$lib/components/ui/sheet/index.js";
    import * as Select from "$lib/components/ui/select/index.js";
    import * as Alert from "$lib/components/ui/alert/index.js";

    import { Input } from "$lib/components/ui/input/index.js";
    import { type ColumnDef, getCoreRowModel } from "@tanstack/table-core";
    import {
        createSvelteTable,
        FlexRender,
    } from "$lib/components/ui/data-table/index.js";
    import * as Table from "$lib/components/ui/table/index.js";
    import DataTable from "../../../../../data-table.svelte";
    import { Root, Textarea } from "$lib/components/ui/textarea";
    import secrets, { type Payment, columns } from "../../../../../stores.ts";
    import { onMount, type Snippet } from "svelte";
    import CreateSecretsForm from "../../../../../create-secrets-form.svelte";
    import type { PageData } from "./$types.d.ts";
    import { AlertCircleIcon } from "@lucide/svelte";
    import { page } from "$app/state";

    const props: {
        data: PageData;
        children?: Snippet;
    } = $props();

    $effect(() => {
        fetch(
            `http://localhost:2323/v1/projects/${page.params.projectId}/secrets`,
        ).then((res) =>
            res.json().then((json) => {
                // todo: types.
                $secrets = json;
            }),
        );
    });
</script>

<div class="w-full h-full px-10 bg-background flex flex-col gap-3 relative">
    {#if page.params.namespaceId && page.params.projectId}
        <Alert.Root variant="destructive">
            <AlertCircleIcon />
            <Alert.Title
                >Your project's encryption key is rotating soon</Alert.Title
            >
        </Alert.Root>
        <Sheet.Root>
            <Sheet.Trigger
                class={`max-w-max ${buttonVariants({ variant: "default", size: "sm" })}`}
                >Add Secret</Sheet.Trigger
            >
            <Sheet.Content>
                <Sheet.Header>
                    <Sheet.Title>Create new secret</Sheet.Title>
                    <Sheet.Description>
                        This will add a new secret under your currently selected
                        project.
                    </Sheet.Description>
                </Sheet.Header>
                <CreateSecretsForm
                    data={props.data}
                    projectId={page.params.projectId}
                />
            </Sheet.Content>
        </Sheet.Root>
        <DataTable data={$secrets} {columns} />
    {/if}
</div>

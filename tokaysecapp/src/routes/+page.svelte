<script lang="ts" generics="TData, TValue">
    import "../app.css";
    import { Button, buttonVariants } from "$lib/components/ui/button/index.ts";
    import * as Sheet from "$lib/components/ui/sheet/index.js";
    import * as Select from "$lib/components/ui/select/index.js";
    import { Input } from "$lib/components/ui/input/index.js";
    import { type ColumnDef, getCoreRowModel } from "@tanstack/table-core";
    import {
        createSvelteTable,
        FlexRender,
    } from "$lib/components/ui/data-table/index.js";
    import * as Table from "$lib/components/ui/table/index.js";
    import DataTable from "./data-table.svelte";
    import { Textarea } from "$lib/components/ui/textarea";
    import secrets, { type Payment, columns } from "./stores.ts";
    import { onMount } from "svelte";
    import CreateSecretsForm from "./create-secrets-form.svelte";
    import type { PageData } from "./$types.d.ts";
    let { data }: { data: PageData } = $props();
    onMount(() => {
        fetch(
            "http://localhost:2323/v1/projects/7352141003882500096/secrets",
        ).then((res) =>
            res.json().then((json) => {
                // todo: types.
                $secrets = json;
            }),
        );
    });
    const fruits = [{ value: "key-value", label: "key value" }];

    let value = $state("");
    const triggerContent = $derived(
        fruits.find((f) => f.value === value)?.label ?? "Select a secret type",
    );
    /**
     * 
     * 
     * <div class="grid flex-1 auto-rows-min gap-3 px-4">
                <Select.Root type="single" name="favoriteFruit" bind:value>
                    <Select.Trigger class="w-full">
                        {triggerContent}
                    </Select.Trigger>
                    <Select.Content>
                        <Select.Group>
                            <!-- <Select.Label>Fruits</Select.Label> -->
                            {#each fruits as fruit (fruit.value)}
                                <Select.Item
                                    value={fruit.value}
                                    label={fruit.label}
                                    disabled={fruit.value === "grapes"}
                                >
                                    {fruit.label}
                                </Select.Item>
                            {/each}
                        </Select.Group>
                    </Select.Content>
                </Select.Root>
                <Input type="text" placeholder="name" />
                <Textarea placeholder="describe this secret (optional)" />
                <Input type="password" placeholder="secret value" />
            </div>
            <Sheet.Footer>
                <Sheet.Close class={buttonVariants({ variant: "default" })}
                    >Create</Sheet.Close
                >
            </Sheet.Footer>
    */
</script>

<div class="w-full h-full p-10 bg-background flex flex-col gap-3 relative">
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
            <CreateSecretsForm {data} />
        </Sheet.Content>
    </Sheet.Root>
    <DataTable data={$secrets} {columns} />
</div>

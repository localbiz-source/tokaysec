import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
import { Checkbox } from "$lib/components/ui/checkbox/index.js";
import CopyIDButton from "$lib/components/CopyIDButton.svelte";

import {
    type ColumnDef,
    type ColumnFiltersState,
    type PaginationState,
    type RowSelectionState,
    type SortingState,
    type VisibilityState,
    getCoreRowModel,
    getFilteredRowModel,
    getPaginationRowModel,
    getSortedRowModel
} from "@tanstack/table-core";
import { createRawSnippet } from "svelte";
import * as Table from "$lib/components/ui/table/index.js";
import { Button } from "$lib/components/ui/button/index.js";
import * as DropdownMenu from "$lib/components/ui/dropdown-menu/index.js";
import { Input } from "$lib/components/ui/input/index.js";
import {
    FlexRender,
    createSvelteTable,
    renderComponent,
    renderSnippet
} from "$lib/components/ui/data-table/index.js";
import { writable, type Writable } from "svelte/store";
export type Payment = {
    id: string;
    name: string;
    store_used: string;
};
export const columns: ColumnDef<Payment>[] = [
    {
        id: "select",
        header: ({ table }) =>
            renderComponent(Checkbox, {
                checked: table.getIsAllPageRowsSelected(),
                indeterminate:
                    table.getIsSomePageRowsSelected() &&
                    !table.getIsAllPageRowsSelected(),
                onCheckedChange: (value) => table.toggleAllPageRowsSelected(!!value),
                "aria-label": "Select all"
            }),
        cell: ({ row }) =>
            renderComponent(Checkbox, {
                checked: row.getIsSelected(),
                onCheckedChange: (value) => row.toggleSelected(!!value),
                "aria-label": "Select row"
            }),
        enableSorting: false,
        enableHiding: false
    },
    {
        accessorKey: "id",
        header: "id",
        cell: ({ row }) => renderComponent(CopyIDButton, { id: row.getValue<string>("id") })
    },
    {
        accessorKey: "name",
        header: "name",
        cell: ({ row }) => {
            const statusSnippet = createRawSnippet<[string]>((getName) => {
                const name = getName();
                return {
                    render: () => `<div class="capitalize">${name}</div>`
                };
            });
            return renderSnippet(statusSnippet, row.getValue("name"));
        }

    },
    {
        accessorKey: "store_used",
        header: "store used",
        cell: ({ row }) => {
            const statusSnippet = createRawSnippet<[string]>((getStoreUsed) => {
                const store_used = getStoreUsed();
                return {
                    render: () => `<div class="capitalize">${store_used}</div>`
                };
            });
            return renderSnippet(statusSnippet, row.getValue("store_used"));
        }

    }
];
const secrets: Writable<Payment[]> = writable([]);
export default secrets;
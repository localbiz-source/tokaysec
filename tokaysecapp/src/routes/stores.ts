import type { ColumnDef } from "@tanstack/table-core";
import { writable, type Writable } from "svelte/store";
export type Payment = {
    id: string;
    name: string;
    store_used: string;
};
export const columns: ColumnDef<Payment>[] = [
    {
        accessorKey: "id",
        header: "id",
    },
    {
        accessorKey: "name",
        header: "name",
    },
    {
        accessorKey: "store_used",
        header: "store used",
    }
];
const secrets: Writable<Payment[]> = writable([]);
export default secrets;
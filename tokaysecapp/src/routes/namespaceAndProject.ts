import type { ColumnDef } from "@tanstack/table-core";
import { writable, type Writable } from "svelte/store";
export type SelectedNamespaceAndProject = {
    namespace?: string;
    project?: string;
};
const global_state: Writable<SelectedNamespaceAndProject> = writable({});
export default global_state;
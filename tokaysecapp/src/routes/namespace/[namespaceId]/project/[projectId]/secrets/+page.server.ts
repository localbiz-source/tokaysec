import type { PageServerLoad, Actions } from "./$types.d.ts";
import { superValidate } from "sveltekit-superforms";
import { createSecretFormSchema } from "./schema.ts";
import { zod } from "sveltekit-superforms/adapters";
import { fail } from "@sveltejs/kit";

export const load: PageServerLoad = async () => {
    return {
        form: await superValidate(zod(createSecretFormSchema)),
    };
};
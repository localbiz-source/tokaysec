import type { PageServerLoad, Actions } from "./$types.d.ts";
import { superValidate } from "sveltekit-superforms";
import { createSecretFormSchema } from "./schema";
import { zod } from "sveltekit-superforms/adapters";
import { fail } from "@sveltejs/kit";
export const load: PageServerLoad = async () => {
    return {
        form: await superValidate(zod(createSecretFormSchema)),
    };
};
export const actions: Actions = {
    default: async (event) => {
        const form = await superValidate(event, zod(createSecretFormSchema));
        if (!form.valid) {
            return fail(400, {
                form,
            });
        }
        const encoder = new TextEncoder();
        const secretArray: Uint8Array = encoder.encode(form.data.secret);

        await fetch("http://localhost:2323/v1/store/kv_store", {
            "method": "POST",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": JSON.stringify({
                "name": form.data.name,
                "value": Array.from(secretArray)
            })
        })
        return {
            form,
        };
    },
};
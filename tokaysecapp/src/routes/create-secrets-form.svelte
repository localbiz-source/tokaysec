<script lang="ts">
    import * as Form from "$lib/components/ui/form/index.js";
    import { Input } from "$lib/components/ui/input/index.js";
    import * as Select from "$lib/components/ui/select/index.js";
    import Textarea from "$lib/components/ui/textarea/textarea.svelte";
    import { createSecretFormSchema, type FormSchema } from "./schema";
    import {
        type SuperValidated,
        type Infer,
        superForm,
    } from "sveltekit-superforms";
    import { zodClient } from "sveltekit-superforms/adapters";

    let { data }: { data: { form: SuperValidated<Infer<FormSchema>> } } =
        $props();

    const form = superForm(data.form, {
        validators: zodClient(createSecretFormSchema),
    });

    const { form: formData, enhance } = form;
    const secretStores = [{ value: "key-value", label: "key value" }];
    const triggerContent = $derived(
        secretStores.find((f) => f.value === $formData.secret_type)?.label ??
            "Select a secret store",
    );
    /*
Fy$Qv7ZBpNNfJGNa6PPM^$pVr@tt7!63TS47oTrC6$ccA74cpRnUxQMsFByHsBThM9zFJ9La6YZ8SiNy!aTmg6CUJCLGPCgo*G5nneJup*kDFU@XC*asMYBhBnq#neoc


tpm2_flushcontext -T "swtpm:port=2321" --loaded-session
tpm2_flushcontext -T "swtpm:port=2321" --saved-session
tpm2_flushcontext -T "swtpm:port=2321" --transient-object
    */
    // curl http://localhost:2323/v1/store/kv_store -X POST -H 'Content-Type: application/json' -d '{"name":"Second Secret","value":[72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]}'
</script>

<form method="POST" use:enhance class="grid flex-1 auto-rows-min gap-3 px-4">
    <Form.Field {form} name="secret_type">
        <Form.Control>
            {#snippet children({ props })}
                <Form.Label>Secret Store</Form.Label>
                <Select.Root
                    {...props}
                    type="single"
                    name="secretStore"
                    bind:value={$formData.secret_type}
                >
                    <Select.Trigger class="w-full">
                        {triggerContent}
                    </Select.Trigger>
                    <Select.Content>
                        <Select.Group>
                            <Select.Label>Key-Value Stores</Select.Label>
                            <!-- disabled={secret_store.value === "grapes"} -->
                            {#each secretStores as secret_store (secret_store.value)}
                                <Select.Item
                                    value={secret_store.value}
                                    label={secret_store.label}
                                >
                                    {secret_store.label}
                                </Select.Item>
                            {/each}
                        </Select.Group>
                    </Select.Content>
                </Select.Root>
            {/snippet}
        </Form.Control>
        <Form.Description>What secret store should store this?</Form.Description
        >
        <Form.FieldErrors />
    </Form.Field>
    <Form.Field {form} name="name">
        <Form.Control>
            {#snippet children({ props })}
                <Form.Label>Name</Form.Label>
                <Input {...props} bind:value={$formData.name} />
            {/snippet}
        </Form.Control>
        <Form.Description
            >A display name to know which secret is which.</Form.Description
        >
        <Form.FieldErrors />
    </Form.Field>
    <Form.Field {form} name="description">
        <Form.Control>
            {#snippet children({ props })}
                <Form.Label>Description</Form.Label>
                <Textarea {...props} class="max-w-[22rem] w-full" bind:value={$formData.description} />
            {/snippet}
        </Form.Control>
        <Form.Description
            >Optionally explain the secret a little more.</Form.Description
        >
        <Form.FieldErrors />
    </Form.Field>
    <Form.Field {form} name="secret">
        <Form.Control>
            {#snippet children({ props })}
                <Form.Label>Value</Form.Label>
                <Textarea {...props} class="max-w-[22rem] w-full" bind:value={$formData.secret} />
            {/snippet}
        </Form.Control>
        <Form.Description>The actual secret value to store</Form.Description>
        <Form.FieldErrors />
    </Form.Field>
    <Form.Button size="sm">Submit</Form.Button>
</form>

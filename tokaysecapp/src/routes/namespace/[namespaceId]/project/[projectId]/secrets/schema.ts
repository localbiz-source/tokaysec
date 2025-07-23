import { z } from "zod";

export const createSecretFormSchema = z.object({
    name: z.string().min(2).max(50),
    description: z.string().min(2).optional(),
    secret_type: z.enum(["key-value"]),
    secret: z.string().min(1),
});

export type FormSchema = typeof createSecretFormSchema;